// Package controller keeps each SignariConfig's file applied (6.23).
//
// It is the config-as-code path run as a reconciler: plan the file through the
// Admin API, apply it when the plan has changes, with the planned version as
// If-Match so an apply never lands on a deployment that moved after it was
// planned, and plan again every resync so a change made another way, from the
// console or the CLI, is put back. Nothing here talks to the database or knows a
// kind of configuration: the file is the engine's to read, and every refusal
// comes back from it, named.
package controller

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"signari.dev/operator/api/v1alpha1"
	"signari.dev/operator/internal/admin"
)

// Reconciler reconciles SignariConfigs.
type Reconciler struct {
	client.Client
	// NewAdmin makes the Admin API client for an endpoint, token and CA.
	NewAdmin func(endpoint, token string, caPEM []byte) (admin.Client, error)
	// Now is the clock, for the status.
	Now func() time.Time
}

const (
	defaultResync = 300 * time.Second
	// retryAfter is how soon a resource that could not be planned is tried again:
	// soon enough to notice a fix, not so soon a broken one floods the engine.
	retryAfter = 60 * time.Second
	readyType  = "Ready"
)

// Reconcile plans the resource's file and applies it when it has changes.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var sc v1alpha1.SignariConfig
	if err := r.Get(ctx, req.NamespacedName, &sc); err != nil {
		// Deleted: nothing is undone. What the file made stays, as it would after
		// `signari apply`; prune is the file's to ask for, not a deletion's.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	resync := defaultResync
	if sc.Spec.ResyncSeconds > 0 {
		resync = time.Duration(sc.Spec.ResyncSeconds) * time.Second
	}

	token, err := r.secretValue(ctx, sc.Namespace, sc.Spec.TokenSecretRef, "token")
	if err != nil {
		return r.fail(ctx, &sc, "TokenUnavailable", err)
	}
	// A Secret made from a file holds the file's last newline, and a token with one
	// is no header value at all (found on kind: every plan failed before it was sent).
	token = strings.TrimSpace(token)
	var caPEM []byte
	if sc.Spec.CASecretRef != nil {
		ca, err := r.secretValue(ctx, sc.Namespace, *sc.Spec.CASecretRef, "ca.crt")
		if err != nil {
			return r.fail(ctx, &sc, "CAUnavailable", err)
		}
		caPEM = []byte(ca)
	}
	api, err := r.NewAdmin(sc.Spec.Endpoint, token, caPEM)
	if err != nil {
		return r.fail(ctx, &sc, "EndpointInvalid", err)
	}

	plan, err := api.Plan(ctx, sc.Spec.Organization, sc.Spec.Document, sc.Spec.Prune)
	if err != nil {
		return r.fail(ctx, &sc, "PlanFailed", err)
	}
	sc.Status.ObservedGeneration = sc.Generation
	if len(plan.Changes) == 0 {
		sc.Status.ConfigVersion = plan.ConfigVersion
		meta.SetStatusCondition(&sc.Status.Conditions, metav1.Condition{Type: readyType,
			Status: metav1.ConditionTrue, Reason: "InSync", ObservedGeneration: sc.Generation,
			Message: fmt.Sprintf("the deployment matches the file at configuration version %d", plan.ConfigVersion)})
		return ctrl.Result{RequeueAfter: resync}, r.Status().Update(ctx, &sc)
	}

	applied, err := api.Apply(ctx, sc.Spec.Organization, sc.Spec.Document, sc.Spec.Prune, plan.ConfigVersion)
	if errors.Is(err, admin.ErrMoved) {
		// Planned against a version the deployment has since left: plan again now,
		// against what is there.
		return ctrl.Result{Requeue: true}, nil
	}
	if err != nil {
		return r.fail(ctx, &sc, "ApplyFailed", err)
	}
	if len(applied.Minted) > 0 {
		name, err := r.keepMinted(ctx, &sc, applied.Minted)
		if err != nil {
			// The apply happened and its secrets were answered once: say so loudly,
			// since they cannot be asked for again.
			return r.fail(ctx, &sc, "MintedNotKept", fmt.Errorf("the apply minted %d secret(s) and they could "+
				"not be written to a Secret, so they are lost: %w", len(applied.Minted), err))
		}
		sc.Status.MintedSecret = name
	}
	now := metav1.NewTime(r.now())
	sc.Status.ConfigVersion = applied.ConfigVersion
	sc.Status.LastApplied = &now
	sc.Status.Created, sc.Status.Updated, sc.Status.Deleted = applied.Create, applied.Update, applied.Delete
	meta.SetStatusCondition(&sc.Status.Conditions, metav1.Condition{Type: readyType, Status: metav1.ConditionTrue,
		Reason: "Applied", ObservedGeneration: sc.Generation,
		Message: fmt.Sprintf("applied %d change(s): %d created, %d updated, %d deleted, configuration version %d",
			len(applied.Changes), applied.Create, applied.Update, applied.Delete, applied.ConfigVersion)})
	return ctrl.Result{RequeueAfter: resync}, r.Status().Update(ctx, &sc)
}

// fail records why the resource is not applied and tries again later.
func (r *Reconciler) fail(ctx context.Context, sc *v1alpha1.SignariConfig, reason string, err error) (ctrl.Result, error) {
	meta.SetStatusCondition(&sc.Status.Conditions, metav1.Condition{Type: readyType, Status: metav1.ConditionFalse,
		Reason: reason, Message: err.Error(), ObservedGeneration: sc.Generation})
	if uerr := r.Status().Update(ctx, sc); uerr != nil {
		return ctrl.Result{}, uerr
	}
	return ctrl.Result{RequeueAfter: retryAfter}, nil
}

func (r *Reconciler) secretValue(ctx context.Context, namespace string, ref v1alpha1.SecretKeyRef,
	defaultKey string) (string, error) {
	key := ref.Key
	if key == "" {
		key = defaultKey
	}
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &s); err != nil {
		return "", fmt.Errorf("reading Secret %s: %w", ref.Name, err)
	}
	v, ok := s.Data[key]
	if !ok || len(v) == 0 {
		return "", fmt.Errorf("secret %s has no %q", ref.Name, key)
	}
	return string(v), nil
}

var secretKeyChars = regexp.MustCompile(`[^-._a-zA-Z0-9]+`)

// keepMinted writes what an apply minted into a Secret the resource owns, one key
// per thing, kind.name: the engine answers each once and never again, and status
// is no place for a secret.
func (r *Reconciler) keepMinted(ctx context.Context, sc *v1alpha1.SignariConfig, minted []admin.Minted) (string,
	error) {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: sc.Name + "-minted", Namespace: sc.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, s, func() error {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		for _, m := range minted {
			s.Data[secretKeyChars.ReplaceAllString(m.Kind+"."+m.Name, "-")] = []byte(m.Secret)
		}
		return controllerutil.SetControllerReference(sc, s, r.Scheme())
	})
	return s.Name, err
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager runs the reconciler for SignariConfigs. A change to the spec
// reconciles at once; a status write, which is the reconciler's own, does not.
// Secrets are not watched: the manager reads them from the API server when asked
// (main.go), so the operator holds no copy of every Secret in the cluster and needs
// no right to list them.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SignariConfig{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
