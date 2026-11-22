package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// What every resource beyond the client shares (6.17): the provider's data
// from Configure, the diagnostic a refused precondition becomes, and the
// writes, each one through the apply's write chain.

// configured is the provider's data, or nil before the provider is configured.
func configured(given any, diags *diag.Diagnostics) *providerData {
	if given == nil {
		return nil
	}
	data, ok := given.(*providerData)
	if !ok {
		diags.AddError("unexpected provider data", fmt.Sprintf("got %T", given))
		return nil
	}
	return data
}

// failed records a failed write: a refused precondition with its remedy,
// anything else as what was being done.
func failed(diags *diag.Diagnostics, doing string, err error) {
	var conflict *signari.ErrConflict
	if errors.As(err, &conflict) {
		diags.AddError("the configuration changed since this plan was made", conflict.Error())
		return
	}
	diags.AddError(doing, err.Error())
}

// create posts a new object through the write chain, answering its id.
func (d *providerData) create(ctx context.Context, path string, body any) (string, int64, error) {
	var id string
	var version int64
	err := d.write(0, func(ifMatch int64) (int64, error) {
		var err error
		id, version, err = d.client.Create(ctx, path, body, ifMatch)
		return version, err
	})
	return id, version, err
}

// change sends a write to an object read at version read.
func (d *providerData) change(ctx context.Context, method, path string, body any, read int64) (int64, error) {
	var version int64
	err := d.write(read, func(ifMatch int64) (int64, error) {
		var err error
		version, err = d.client.Write(ctx, method, path, body, ifMatch)
		return version, err
	})
	return version, err
}

// remove deletes an object read at version read; one already gone is not an
// error, since destroying it is what was asked.
func (d *providerData) remove(ctx context.Context, path string, read int64) error {
	_, err := d.change(ctx, http.MethodDelete, path, nil, read)
	if errors.Is(err, signari.ErrNotFound) {
		return nil
	}
	return err
}

// idAttribute is a server-assigned id, kept across plans.
func idAttribute(what string) schema.StringAttribute {
	return schema.StringAttribute{
		Computed:            true,
		MarkdownDescription: "The " + what + "'s id, assigned by the server.",
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

// versionAttribute is config_version, as signari_client describes it.
func versionAttribute() schema.Int64Attribute {
	return schema.Int64Attribute{
		Computed: true,
		MarkdownDescription: "The deployment's configuration version when this resource was last read, " +
			"sent as `If-Match` on its next write.",
	}
}

// replacing is a required string whose change replaces the object.
func replacing(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Required:            true,
		MarkdownDescription: description + " Changing it replaces the object.",
		PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
	}
}
