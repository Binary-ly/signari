package saml

import (
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// The topmost StatusCode is one of the four top-level values, and a
// second-level code sits beneath one (saml-core-2.0-os lines 1628-1645).
// Requester was nested under Responder, which both broke that MUST and told
// the provider the fault was ours.
func TestTheTopmostStatusCodeIsATopLevelValue(t *testing.T) {
	for _, c := range []struct {
		status, top, sub string
	}{
		{StatusRequester, StatusRequester, ""},
		{StatusResponder, StatusResponder, ""},
		{StatusNoPassive, StatusResponder, StatusNoPassive},
		{StatusRequestDenied, StatusResponder, StatusRequestDenied},
	} {
		doc, err := BuildStatusResponse(StatusInput{Issuer: "https://idp.test", Destination: "https://sp.test/acs",
			InResponse: "_r", Status: c.status, Now: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		d := etree.NewDocument()
		if err := d.ReadFromString(doc); err != nil {
			t.Fatal(err)
		}
		top := d.FindElement("//Status/StatusCode")
		if top == nil || top.SelectAttrValue("Value", "") != c.top {
			t.Errorf("%s: topmost StatusCode is %v, want %s", c.status, top, c.top)
			continue
		}
		sub := top.FindElement("./StatusCode")
		got := ""
		if sub != nil {
			got = sub.SelectAttrValue("Value", "")
		}
		if got != c.sub {
			t.Errorf("%s: nested StatusCode is %q, want %q", c.status, got, c.sub)
		}
		if strings.Count(doc, "StatusCode Value=") > 2 {
			t.Errorf("%s: more than two levels of StatusCode", c.status)
		}
	}
}
