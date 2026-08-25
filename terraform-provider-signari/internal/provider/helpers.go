package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// listToStrings converts a Terraform list to a Go slice.
//
// A null or unknown list yields nil rather than an error: "not set" and "an
// empty list" are the same thing to the API, and making the caller distinguish
// them would push a Terraform detail into the request body.
func listToStrings(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(l.ElementsAs(ctx, &out, false)...)
	return out
}

// decodeInto parses a response body, ignoring a body that does not fit.
//
// Deliberately lossy. The fields being read are optional extras -- a secret shown
// once, a version -- and a response that omits them is not an error. What would
// be an error is a failed WRITE, and that is decided by the status code before
// this is ever called.
func decodeInto(body []byte, v any) {
	_ = json.Unmarshal(body, v)
}

// pick returns the first non-zero of two versions.
//
// The ETag header is authoritative; the body's config_version is the fallback
// for a response that carried one and no header. Both are populated by this
// server, and preferring the header means the provider keeps working against one
// that stops putting the version in the body.
func pick(header, body int64) int64 {
	if header > 0 {
		return header
	}
	return body
}

// boolRequiresReplace is RequiresReplace for a bool attribute.
func boolRequiresReplace() planmodifier.Bool {
	return boolplanmodifier.RequiresReplace()
}
