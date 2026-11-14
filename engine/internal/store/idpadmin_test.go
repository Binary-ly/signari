package store

import (
	"reflect"
	"testing"
)

// Every setting a change can carry is a change on its own. Empty is a list kept by hand,
// and StoreTokens was left off it, so a PATCH that only stopped keeping a provider's
// tokens was answered "nothing to change": the console and Terraform could make that
// change only beside another one. Read from the struct, so a field added later is held
// to it too.
func TestEverySettingOfAProviderChangeIsAChange(t *testing.T) {
	typ := reflect.TypeOf(IdentityProviderChange{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.Pointer {
			t.Errorf("%s is not a pointer, so a change cannot leave it alone", f.Name)
			continue
		}
		var c IdentityProviderChange
		reflect.ValueOf(&c).Elem().Field(i).Set(reflect.New(f.Type.Elem()))
		if c.Empty() {
			t.Errorf("a change that sets only %s reads as empty", f.Name)
		}
	}
	if !(IdentityProviderChange{}).Empty() {
		t.Error("a change that sets nothing does not read as empty")
	}
}
