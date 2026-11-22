package saml

import (
	"strings"
	"testing"
)

func logoutAnswer(status, inResponseTo string) []byte {
	return []byte(`<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" InResponseTo="` + inResponseTo + `">
<samlp:Status><samlp:StatusCode Value="` + status + `"/></samlp:Status></samlp:LogoutResponse>
</soap11:Body></soap11:Envelope>`)
}

func TestASOAPAnswerIsReadForWhatItSays(t *testing.T) {
	if err := ReadSOAPLogoutResponse(logoutAnswer(StatusSuccess, "_q"), "_q"); err != nil {
		t.Errorf("a good answer: %v", err)
	}
	for name, c := range map[string]struct {
		body []byte
		want string
	}{
		"it did not":      {logoutAnswer(StatusRequester, "_q"), "answered"},
		"another request": {logoutAnswer(StatusSuccess, "_other"), "not this request"},
		"no answer":       {[]byte(`<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body/></soap11:Envelope>`), "no LogoutResponse"},
		"a fault": {[]byte(`<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body>
<soap11:Fault><faultcode>Server</faultcode><faultstring>no such session</faultstring></soap11:Fault></soap11:Body></soap11:Envelope>`), "no such session"},
		"a DOCTYPE":    {[]byte(`<!DOCTYPE x [<!ENTITY a "b">]><x/>`), "DOCTYPE"},
		"not even XML": {[]byte(`<oops`), "parse"},
	} {
		err := ReadSOAPLogoutResponse(c.body, "_q")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
