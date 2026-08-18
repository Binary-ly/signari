package rar

import (
	"strings"
	"testing"
)

// A registry shaped like the RFC's running example.
func testRegistry() Registry {
	return Registry{
		"account_information": {
			Type:     "account_information",
			Fields:   []string{FieldActions, FieldLocations, FieldDatatypes},
			Required: []string{FieldActions},
		},
		"payment_initiation": {
			Type:     "payment_initiation",
			Fields:   []string{FieldActions, FieldLocations, FieldIdentifier},
			Required: []string{FieldActions, FieldIdentifier},
		},
	}
}

func parseAndValidate(t *testing.T, raw string) error {
	t.Helper()
	details, objs, err := Parse(raw)
	if err != nil {
		return err
	}
	return Validate(details, objs, testRegistry())
}

func TestAWellFormedRequestIsAccepted(t *testing.T) {
	err := parseAndValidate(t, `[
		{"type":"account_information","actions":["list_accounts","read_balances"],
		 "locations":["https://example.com/accounts"]}
	]`)
	if err != nil {
		t.Fatalf("a conformant request was refused: %v", err)
	}
}

// §5, all five conditions. An implementation that checks four of them refuses
// four kinds of bad request and grants the fifth, so each gets its own case.
func TestEveryRejectionConditionOfSection5(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{
			name: "unknown authorization details type",
			body: `[{"type":"nuclear_launch","actions":["fire"]}]`,
			want: "does not know",
		},
		{
			name: "known type with an unknown field",
			body: `[{"type":"account_information","actions":["list_accounts"],
			         "sneaky":"value"}]`,
			want: "unknown field",
		},
		{
			name: "known common field the type did not register",
			body: `[{"type":"account_information","actions":["list_accounts"],
			         "privileges":["admin"]}]`,
			want: "does not use",
		},
		{
			name: "field of the wrong type: array where a string belongs",
			body: `[{"type":"payment_initiation","actions":["initiate"],
			         "identifier":["a","b"]}]`,
			want: "must be a string",
		},
		{
			name: "field of the wrong type: string where an array belongs",
			body: `[{"type":"account_information","actions":"list_accounts"}]`,
			want: "must be an array",
		},
		{
			name: "missing a required field",
			body: `[{"type":"payment_initiation","actions":["initiate"]}]`,
			want: "missing the required field",
		},
		{
			name: "invalid value: an empty action",
			body: `[{"type":"account_information","actions":["list_accounts",""]}]`,
			want: "empty value",
		},
		{
			name: "no type at all",
			body: `[{"actions":["list_accounts"]}]`,
			want: "no type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseAndValidate(t, tc.body)
			if err == nil {
				t.Fatalf("accepted, and §5 requires %s", ErrorCode)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// §2 says the parameter is a JSON array. A single object is the mistake people
// actually make, and "invalid JSON" sends them hunting a syntax error.
func TestASingleObjectIsRefusedWithAUsefulMessage(t *testing.T) {
	err := parseAndValidate(t, `{"type":"account_information","actions":["list_accounts"]}`)
	if err == nil {
		t.Fatal("a bare object was accepted where an array is required")
	}
	if !strings.Contains(err.Error(), "wrap it in") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

// Duplicate members make the permission depend on the parser. These objects ARE
// permissions, so there is no reading of them this server may pick.
func TestDuplicateMembersAreRefused(t *testing.T) {
	err := parseAndValidate(t,
		`[{"type":"account_information","actions":["list_accounts"],"actions":["transfer"]}]`)
	if err == nil {
		t.Fatal("an object naming `actions` twice was accepted; which permission " +
			"applies would depend on the JSON parser")
	}
}

// An empty array is not the same as an absent parameter: a client that sent one
// asked for something, and silently granting nothing tells it otherwise.
func TestAnEmptyArrayIsRefusedAndAnAbsentParameterIsNot(t *testing.T) {
	if err := parseAndValidate(t, `[]`); err == nil {
		t.Error("an empty authorization_details array was accepted silently")
	}
	details, _, err := Parse("")
	if err != nil || details != nil {
		t.Errorf("an absent parameter should be absent, got %v / %v", details, err)
	}
}

// §6/§6.1: a token request may narrow what was granted, never widen it. The
// specification is explicit that no standard comparison exists, so ours is
// subset containment — the one comparison that cannot accidentally widen.
func TestNarrowingIsAllowedAndWideningIsNot(t *testing.T) {
	granted := []Detail{{
		Type:      "account_information",
		Actions:   []string{"list_accounts", "read_balances", "read_transactions"},
		Locations: []string{"https://example.com/accounts"},
	}}

	t.Run("a subset is granted", func(t *testing.T) {
		got, err := Narrow(granted, []Detail{{
			Type: "account_information", Actions: []string{"list_accounts"},
		}})
		if err != nil {
			t.Fatalf("narrowing was refused: %v", err)
		}
		if len(got) != 1 || len(got[0].Actions) != 1 {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("an action that was never granted is refused", func(t *testing.T) {
		if _, err := Narrow(granted, []Detail{{
			Type: "account_information", Actions: []string{"transfer_funds"},
		}}); err == nil {
			t.Fatal("a token request obtained an action the grant never authorized")
		}
	})

	t.Run("a location that was never granted is refused", func(t *testing.T) {
		if _, err := Narrow(granted, []Detail{{
			Type: "account_information", Actions: []string{"list_accounts"},
			Locations: []string{"https://attacker.test/accounts"},
		}}); err == nil {
			t.Fatal("a token request widened the locations")
		}
	})

	t.Run("a type that was never granted is refused", func(t *testing.T) {
		if _, err := Narrow(granted, []Detail{{
			Type: "payment_initiation", Actions: []string{"initiate"},
		}}); err == nil {
			t.Fatal("a token request obtained a type the grant never authorized")
		}
	})

	t.Run("asking for nothing keeps everything", func(t *testing.T) {
		got, err := Narrow(granted, nil)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %+v / %v; §6 makes the parameter optional at the token "+
				"endpoint, and omitting it keeps the grant as authorized", got, err)
		}
	})
}

// The identifier is a scalar, so containment means equality. A request naming a
// different account is not a narrowing of one naming this account.
func TestADifferentIdentifierIsNotANarrowing(t *testing.T) {
	granted := []Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-1",
	}}
	if _, err := Narrow(granted, []Detail{{
		Type: "payment_initiation", Actions: []string{"initiate"}, Identifier: "acct-2",
	}}); err == nil {
		t.Fatal("a payment against a different account was treated as a narrowing " +
			"of one against this account")
	}
}

// §10 feeds the discovery document, which clients cache and compare.
func TestRegisteredTypesAreSorted(t *testing.T) {
	got := testRegistry().Types()
	if len(got) != 2 || got[0] != "account_information" || got[1] != "payment_initiation" {
		t.Fatalf("Types() = %v, want sorted", got)
	}
}
