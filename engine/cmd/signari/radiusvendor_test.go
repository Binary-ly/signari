package main

import "testing"

// The value is a device's own syntax and is full of `=` and `:`, so only the
// first of each divides.
func TestAVendorAttributeIsReadFromTheCommandLine(t *testing.T) {
	got, err := parseVendorAttribute("9:1=shell:priv-lvl=15")
	if err != nil {
		t.Fatal(err)
	}
	if got.Vendor != 9 || got.Type != 1 || got.Value != "shell:priv-lvl=15" {
		t.Errorf("read %+v", got)
	}
	for _, bad := range []string{"", "9", "9:1", "9=x", "x:1=v", "9:x=v", "0:1=v", "9:0=v", "9:256=v", "4294967296:1=v", "9:1="} {
		if a, err := parseVendorAttribute(bad); err == nil {
			t.Errorf("%q was read as %+v", bad, a)
		}
	}

	list, err := parseVendorAttributes(" 9:1=a=b , 311:2=c ")
	if err != nil || len(list) != 2 || list[0].Value != "a=b" || list[1].Vendor != 311 {
		t.Errorf("read %+v, %v", list, err)
	}
	if list, err := parseVendorAttributes(""); list != nil || err != nil {
		t.Errorf("nothing was read as %+v, %v", list, err)
	}
	// A comma in a value leaves a piece that is not an attribute, which is refused
	// rather than sent as half of one.
	if list, err := parseVendorAttributes("9:1=a,b"); err == nil {
		t.Errorf("a value with a comma was read as %+v", list)
	}
}
