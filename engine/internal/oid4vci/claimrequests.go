package oid4vci

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"

	"signari.dev/engine/internal/rar"
)

// What a wallet asks to have in a credential (12.06): `claims` in an
// openid_credential detail (specs/oid4vci.txt:1262), each a claims description object
// (:4070-4090). It was accepted and then lost, since nothing decoded it, so a wallet
// that marked a claim mandatory was given a credential without it and nothing said so.

// maxClaimRequests bounds one detail's list, which is compared pairwise.
const maxClaimRequests = 64

// MandatoryClaims reads what a wallet asks of c, refusing what Appendix B.3 says
// MUST abort the processing (:4144-4157) and what a claims path pointer is not
// (:4171), and answers the claims of c it will take no credential without. A
// claim c does not carry is refused when mandatory, since no credential could be
// one the wallet takes; when not, it is left out, as the wallet said it could be.
func (c Configuration) MandatoryClaims(asked []rar.ClaimDescription) ([]string, error) {
	if asked == nil {
		return nil, nil
	}
	switch {
	case len(asked) == 0:
		return nil, fmt.Errorf("claims is a non-empty array when it is given (OID4VCI 5.1.1)")
	case len(asked) > maxClaimRequests:
		return nil, fmt.Errorf("a credential detail may describe at most %d claims", maxClaimRequests)
	}
	for _, d := range asked {
		if err := checkClaimPath(d.Path); err != nil {
			return nil, err
		}
	}
	for i := range asked {
		for j := i + 1; j < len(asked); j++ {
			if err := contradictory(asked[i].Path, asked[j].Path); err != nil {
				return nil, err
			}
		}
	}
	carried := map[string]bool{}
	for _, n := range c.AlwaysClaims {
		carried[n] = true
	}
	for _, n := range c.SelectiveClaims {
		carried[n] = true
	}
	var out []string
	for _, d := range asked {
		if !d.Mandatory {
			continue
		}
		name, ok := c.claimNamed(d.Path)
		if !ok || !carried[name] {
			return nil, fmt.Errorf("the wallet will take no credential without %s, and %s carries no such claim",
				pathText(d.Path), c.ID)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// claimNamed is the claim of this configuration a path starts in: the first key of
// an SD-JWT VC, whose claims are the payload's, or the key under credentialSubject of
// a JWT VC, whose claims are there.
func (c Configuration) claimNamed(path []any) (string, bool) {
	at := 0
	if c.Format == FormatJWTVC {
		if first, ok := path[0].(string); !ok || first != "credentialSubject" || len(path) < 2 {
			return "", false
		}
		at = 1
	}
	name, ok := path[at].(string)
	return name, ok
}

// checkClaimPath holds a path to Appendix C: non-empty, each element a key, a
// non-negative integer, or null (:4171-4193).
func checkClaimPath(path []any) error {
	if len(path) == 0 {
		return fmt.Errorf("a claims description's path is a non-empty array (OID4VCI Appendix C)")
	}
	for _, e := range path {
		switch v := e.(type) {
		case nil, string:
		case float64:
			if v < 0 || v != math.Trunc(v) || v > math.MaxInt32 {
				return fmt.Errorf("%s has an index that is not a non-negative integer", pathText(path))
			}
		default:
			return fmt.Errorf("%s has an element that is not a key, an index or null", pathText(path))
		}
	}
	return nil
}

// contradictory is B.3: the same claim addressed twice, one array addressed whole
// and by an index, or one claim taken for an array by one and an object by the other.
func contradictory(a, b []any) error {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if x == y {
			continue
		}
		xs, xIsKey := x.(string)
		ys, yIsKey := y.(string)
		switch {
		case xIsKey && yIsKey && xs != ys, !xIsKey && !yIsKey && x != nil && y != nil:
			// Two keys of one object, or two indexes of one array: different claims.
			return nil
		case xIsKey != yIsKey:
			return fmt.Errorf("%s and %s take one claim for an array and an object (OID4VCI Appendix B.3)",
				pathText(a), pathText(b))
		default:
			return fmt.Errorf("%s and %s address one array whole and by an index (OID4VCI Appendix B.3)",
				pathText(a), pathText(b))
		}
	}
	if len(a) == len(b) {
		return fmt.Errorf("%s is described twice (OID4VCI Appendix B.3)", pathText(a))
	}
	return nil
}

func pathText(path []any) string {
	raw, _ := json.Marshal(path)
	return string(raw)
}
