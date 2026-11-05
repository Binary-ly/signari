// Package v1alpha1 is the SignariConfig resource: an organisation's configuration
// file, which the operator plans and applies through the engine's Admin API and
// keeps applied (6.23).
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the resource's API group and version.
var GroupVersion = schema.GroupVersion{Group: "signari.dev", Version: "v1alpha1"}

var (
	// SchemeBuilder registers the types with a scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	// AddToScheme adds them.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() { SchemeBuilder.Register(&SignariConfig{}, &SignariConfigList{}) }

// SignariConfig is one organisation's configuration file, kept applied.
type SignariConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SignariConfigSpec   `json:"spec"`
	Status SignariConfigStatus `json:"status,omitempty"`
}

// SignariConfigSpec is what to apply, and where.
type SignariConfigSpec struct {
	// Endpoint is the Admin API's base URL, such as https://signari-admin:8081.
	Endpoint string `json:"endpoint"`
	// Organization is the organisation's id, the {orgID} the file is applied to.
	Organization string `json:"organization"`
	// Document is the configuration file, as `signari apply` reads it
	// (docs/config-as-code.md).
	Document string `json:"document"`
	// Prune deletes what the file does not declare, as `signari apply -prune` does.
	Prune bool `json:"prune,omitempty"`
	// TokenSecretRef names the Secret holding an Admin API token with
	// organizations:write and the scopes the file's kinds need. Key "token" by
	// default.
	TokenSecretRef SecretKeyRef `json:"tokenSecretRef"`
	// CASecretRef names the Secret holding the CA that issued the Admin API's
	// certificate, when it is not one the system trusts. Key "ca.crt" by default.
	CASecretRef *SecretKeyRef `json:"caSecretRef,omitempty"`
	// ResyncSeconds is how often the file is planned again, so a change made
	// another way is put back. 300 when unset.
	ResyncSeconds int32 `json:"resyncSeconds,omitempty"`
}

// SecretKeyRef is a key of a Secret in the resource's namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

// SignariConfigStatus is what the operator last found and did.
type SignariConfigStatus struct {
	// ObservedGeneration is the generation of the spec last planned.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ConfigVersion is the deployment's configuration version after the last plan
	// or apply.
	ConfigVersion int64 `json:"configVersion,omitempty"`
	// LastApplied is when the file last changed something.
	LastApplied *metav1.Time `json:"lastApplied,omitempty"`
	// Created, Updated and Deleted count the last apply's changes.
	Created int `json:"created,omitempty"`
	Updated int `json:"updated,omitempty"`
	Deleted int `json:"deleted,omitempty"`
	// MintedSecret names the Secret the secrets an apply minted were written to.
	MintedSecret string `json:"mintedSecret,omitempty"`
	// Conditions has Ready: True when the deployment matches the file.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SignariConfigList is a list of them.
type SignariConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SignariConfig `json:"items"`
}

// DeepCopyInto copies into out.
func (in *SignariConfig) DeepCopyInto(out *SignariConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.CASecretRef != nil {
		ref := *in.Spec.CASecretRef
		out.Spec.CASecretRef = &ref
	}
	out.Status = in.Status
	if in.Status.LastApplied != nil {
		out.Status.LastApplied = in.Status.LastApplied.DeepCopy()
	}
	if in.Status.Conditions != nil {
		out.Status.Conditions = make([]metav1.Condition, len(in.Status.Conditions))
		for i := range in.Status.Conditions {
			in.Status.Conditions[i].DeepCopyInto(&out.Status.Conditions[i])
		}
	}
}

// DeepCopy copies it.
func (in *SignariConfig) DeepCopy() *SignariConfig {
	if in == nil {
		return nil
	}
	out := new(SignariConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject copies it as a runtime.Object.
func (in *SignariConfig) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopyInto copies into out.
func (in *SignariConfigList) DeepCopyInto(out *SignariConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SignariConfig, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy copies it.
func (in *SignariConfigList) DeepCopy() *SignariConfigList {
	if in == nil {
		return nil
	}
	out := new(SignariConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject copies it as a runtime.Object.
func (in *SignariConfigList) DeepCopyObject() runtime.Object { return in.DeepCopy() }
