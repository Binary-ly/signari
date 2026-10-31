package clients

import (
	"net"
	"net/url"
	"slices"
	"strings"
)

// ProfileFAPI2 is the FAPI 2.0 Security Profile (specs/fapi2.txt).
const ProfileFAPI2 = "fapi2"

// FAPI2Algorithms are what §5.4.1 lets sign a JWT, Ed25519 being the only EdDSA a
// key here can be: "use PS256, ES256, or EdDSA (using the Ed25519 variant)".
var FAPI2Algorithms = []string{"PS256", "ES256", "EdDSA"}

// FAPI2 reports that the client is held to the profile.
func (c *Client) FAPI2() bool { return c.SecurityProfile == ProfileFAPI2 }

// ProfileProblems says what keeps a client from meeting its security profile. One
// answer for where it is set, where it is used and doctor, because a client can move
// out of its profile by a command that has never heard of one. Each is a requirement of
// specs/fapi2.txt on this client's settings; what a request must do is checked on it.
func (c *Client) ProfileProblems() []string {
	if !c.FAPI2() {
		return nil
	}
	var out []string
	if c.Type != "confidential" {
		out = append(out, "it is not a confidential client (§5.3.2.1)")
	}
	if c.TokenEndpointAuthMethod != "private_key_jwt" && !c.TLSExpectation().Configured() {
		out = append(out, "it authenticates by "+c.TokenEndpointAuthMethod+
			", not mutual TLS or private_key_jwt (§5.3.2.1)")
	}
	if !c.DPoPBoundAccessTokens && !c.TLSBoundTokens {
		out = append(out, "its access tokens are not sender-constrained (§5.3.2.1)")
	}
	if !c.RequirePAR {
		out = append(out, "it does not require pushed authorization requests (§5.3.2.2)")
	}
	if !c.RequirePKCE {
		out = append(out, "it does not require PKCE (§5.3.2.2)")
	}
	if c.AllowHybrid || slices.ContainsFunc(c.ResponseTypes, func(t string) bool { return t != "code" }) {
		out = append(out, "it may use a response_type other than code (§5.3.2.2)")
	}
	for _, alg := range []string{c.IDTokenAlg, c.AccessTokenAlg()} {
		if !slices.Contains(FAPI2Algorithms, alg) {
			out = append(out, "its tokens are signed with "+alg+", not "+strings.Join(FAPI2Algorithms, ", ")+" (§5.4.1)")
			break
		}
	}
	for _, uri := range c.RedirectURIs {
		if u, err := url.Parse(uri); err == nil && u.Scheme == "http" && !loopback(u.Hostname()) {
			out = append(out, uri+" is an http redirect URI that is not a loopback address (§5.3.2.2)")
		}
	}
	return out
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}
