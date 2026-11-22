package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"signari.dev/operator/api/v1alpha1"
	"signari.dev/operator/internal/admin"
)

// fakeEngine is the Admin API's config route: a deployment at a version, holding
// the last document applied. A plan of a document that differs from what is held
// has one change; an apply needs If-Match at the current version.
type fakeEngine struct {
	mu       sync.Mutex
	version  int64
	held     string
	minted   []admin.Minted
	refuse   string // an error code every request is answered with
	requests []recorded
}

type recorded struct {
	dryRun        bool
	ifMatch, auth string
	document      string
}

func (e *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var body struct {
		Document string `json:"document"`
		DryRun   bool   `json:"dry_run"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	e.requests = append(e.requests, recorded{dryRun: body.DryRun, ifMatch: r.Header.Get("If-Match"),
		auth: r.Header.Get("Authorization"), document: body.Document})
	if r.URL.Path != "/admin/organizations/org-1/config" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if e.refuse != "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": e.refuse, "detail": "the file names a scope nobody declared"})
		return
	}
	var changes []admin.Change
	if body.Document != e.held {
		changes = []admin.Change{{Action: "create", Kind: "group", Name: "engineering"}}
	}
	out := admin.Result{DryRun: body.DryRun, Changes: changes, Create: len(changes), ConfigVersion: e.version}
	if !body.DryRun {
		if r.Header.Get("If-Match") != `"`+itoa(e.version)+`"` {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		e.held = body.Document
		if len(changes) > 0 {
			e.version++
		}
		out.ConfigVersion, out.Minted = e.version, e.minted
	}
	_ = json.NewEncoder(w).Encode(out)
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func setup(t *testing.T, objs ...client.Object) (*Reconciler, client.Client, *fakeEngine) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.SignariConfig{}).Build()
	engine := &fakeEngine{version: 7}
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	for _, o := range objs {
		if sc, ok := o.(*v1alpha1.SignariConfig); ok && sc.Spec.Endpoint == "" {
			sc.Spec.Endpoint = srv.URL
			if err := c.Update(context.Background(), sc); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &Reconciler{Client: c, NewAdmin: admin.New, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }},
		c, engine
}

func resource(doc string) *v1alpha1.SignariConfig {
	return &v1alpha1.SignariConfig{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "idp", Generation: 1},
		Spec: v1alpha1.SignariConfigSpec{Organization: "org-1", Document: doc,
			TokenSecretRef: v1alpha1.SecretKeyRef{Name: "admin-token"}}}
}

// tokenSecret holds the token as `kubectl create secret --from-file` writes it, with
// the file's last newline: a header value cannot hold one, and on kind every plan
// failed with it until the token was trimmed.
func tokenSecret() *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: "idp"},
		Data: map[string][]byte{"token": []byte("sgnadm_test\n")}}
}

func reconcileOnce(t *testing.T, r *Reconciler) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "idp",
		Name: "acme"}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func current(t *testing.T, c client.Client) *v1alpha1.SignariConfig {
	t.Helper()
	var sc v1alpha1.SignariConfig
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "idp", Name: "acme"}, &sc); err != nil {
		t.Fatal(err)
	}
	return &sc
}

// A new resource is planned, then applied with the planned version as If-Match;
// the next pass finds the deployment in step and applies nothing; a change to the
// file is applied in turn, and a change made another way is put back.
func TestAResourceConverges(t *testing.T) {
	r, c, engine := setup(t, resource("version: 1\ngroups: [engineering]\n"), tokenSecret())

	res := reconcileOnce(t, r)
	sc := current(t, c)
	ready := meta.FindStatusCondition(sc.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionTrue || ready.Reason != "Applied" || sc.Status.ConfigVersion != 8 ||
		sc.Status.Created != 1 || sc.Status.LastApplied == nil || sc.Status.ObservedGeneration != 1 {
		t.Fatalf("after the first pass: %+v, %+v", sc.Status, ready)
	}
	if res.RequeueAfter != defaultResync {
		t.Errorf("the next plan is in %s, want the resync", res.RequeueAfter)
	}
	if len(engine.requests) != 2 || !engine.requests[0].dryRun || engine.requests[1].dryRun ||
		engine.requests[1].ifMatch != `"7"` || engine.requests[0].auth != "Bearer sgnadm_test" {
		t.Fatalf("the engine was asked %+v; want a plan, then an apply with If-Match \"7\"", engine.requests)
	}

	reconcileOnce(t, r)
	if len(engine.requests) != 3 || !engine.requests[2].dryRun {
		t.Errorf("in step, the pass applied: %+v", engine.requests[2:])
	}
	if ready := meta.FindStatusCondition(current(t, c).Status.Conditions, "Ready"); ready.Reason != "InSync" {
		t.Errorf("in step, Ready is %s", ready.Reason)
	}

	// Somebody changes the deployment another way: the next pass puts the file back.
	engine.mu.Lock()
	engine.held, engine.version = "changed in the console", 9
	engine.mu.Unlock()
	reconcileOnce(t, r)
	last := engine.requests[len(engine.requests)-1]
	if last.dryRun || last.ifMatch != `"9"` || last.document != "version: 1\ngroups: [engineering]\n" {
		t.Errorf("a drifted deployment was not put back: %+v", last)
	}
	if current(t, c).Status.ConfigVersion != 10 {
		t.Errorf("after putting it back the version reads %d", current(t, c).Status.ConfigVersion)
	}
}

// Planned against a version the deployment then left: the apply is refused, and
// the reconciler plans again rather than applying a plan nobody saw.
func TestAnApplyOverADeploymentThatMovedIsPlannedAgain(t *testing.T) {
	r, _, engine := setup(t, resource("version: 1\n"), tokenSecret())
	engine.mu.Lock()
	engine.version = 7
	engine.mu.Unlock()
	moved := &movingAdmin{engine: engine}
	r.NewAdmin = func(endpoint, token string, ca []byte) (admin.Client, error) {
		inner, err := admin.New(endpoint, token, ca)
		moved.inner = inner
		return moved, err
	}
	res := reconcileOnce(t, r)
	if !res.Requeue {
		t.Errorf("a refused apply was not planned again: %+v", res)
	}
}

// movingAdmin moves the deployment between the plan and the apply.
type movingAdmin struct {
	inner  admin.Client
	engine *fakeEngine
}

func (m *movingAdmin) Plan(ctx context.Context, org, doc string, prune bool) (*admin.Result, error) {
	res, err := m.inner.Plan(ctx, org, doc, prune)
	m.engine.mu.Lock()
	m.engine.version++
	m.engine.mu.Unlock()
	return res, err
}

func (m *movingAdmin) Apply(ctx context.Context, org, doc string, prune bool, planned int64) (*admin.Result, error) {
	return m.inner.Apply(ctx, org, doc, prune, planned)
}

// What an apply mints is answered once: it goes into a Secret the resource owns,
// one key per thing, and not into the status.
func TestMintedSecretsAreKeptInASecretAndNotInTheStatus(t *testing.T) {
	r, c, engine := setup(t, resource("version: 1\nproviders: [hook]\n"), tokenSecret())
	engine.minted = []admin.Minted{{Kind: "provider", Name: "risk hook", Secret: "whsec_once"}}
	reconcileOnce(t, r)
	sc := current(t, c)
	var s corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "idp", Name: "acme-minted"}, &s); err != nil {
		t.Fatal(err)
	}
	if string(s.Data["provider.risk-hook"]) != "whsec_once" || sc.Status.MintedSecret != "acme-minted" {
		t.Errorf("the minted Secret holds %v and the status names %q", s.Data, sc.Status.MintedSecret)
	}
	if len(s.OwnerReferences) != 1 || s.OwnerReferences[0].Name != "acme" {
		t.Errorf("the minted Secret is owned by %+v", s.OwnerReferences)
	}
	raw, _ := json.Marshal(sc.Status)
	if strings.Contains(string(raw), "whsec_once") {
		t.Error("a minted secret is in the status")
	}
}

// Every way a pass can fail is said in Ready, with the reason, and tried again later.
func TestAPassThatCannotFinishSaysWhyInReady(t *testing.T) {
	r, c, _ := setup(t, resource("version: 1\n"))
	res := reconcileOnce(t, r)
	if ready := meta.FindStatusCondition(current(t, c).Status.Conditions, "Ready"); ready == nil ||
		ready.Status != metav1.ConditionFalse || ready.Reason != "TokenUnavailable" || res.RequeueAfter != retryAfter {
		t.Errorf("without the token Secret: %+v, %+v", ready, res)
	}

	r, c, engine := setup(t, resource("version: 1\nscopes: [nobody]\n"), tokenSecret())
	engine.refuse = "config_refused"
	reconcileOnce(t, r)
	ready := meta.FindStatusCondition(current(t, c).Status.Conditions, "Ready")
	if ready == nil || ready.Reason != "PlanFailed" || !strings.Contains(ready.Message, "config_refused") ||
		!strings.Contains(ready.Message, "nobody declared") {
		t.Errorf("a file the engine refuses: %+v", ready)
	}
	for _, rq := range engine.requests {
		if !rq.dryRun {
			t.Error("a refused plan was applied")
		}
	}
}

// A resource deleted is left alone, and what its file made stays, as after
// `signari apply`.
func TestADeletedResourceIsNotAnError(t *testing.T) {
	r, _, engine := setup(t, tokenSecret())
	res := reconcileOnce(t, r)
	if res != (ctrl.Result{}) || len(engine.requests) != 0 {
		t.Errorf("a deleted resource: %+v, %d requests", res, len(engine.requests))
	}
}
