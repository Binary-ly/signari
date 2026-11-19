package store

import (
	"errors"

	"github.com/jackc/pgx/v5"
)

// FirstOrgOfIssuer is the first organisation of the instance serving an issuer, the one a
// usernameless sign-in, recovery and sign-up are decided under.
//
// It stands on (instance_id, created_at), or it reads and sorts every organisation of the
// instance, on every sign-in (0.74). The instance is found first because a join would lose
// the index's order: through one, the plan seeks the index and sorts what it read all the
// same.
const FirstOrgOfIssuer = `
	SELECT o.id::text FROM core.organizations o
	WHERE o.instance_id = (SELECT i.id FROM core.instances i WHERE i.issuer = $1)
	ORDER BY o.created_at LIMIT 1`

// FirstOrgSignupRule is the sign-up rule of FirstOrgOfIssuer's organisation, asked with
// it in one statement, so a batch needs no answer from another of its statements.
const FirstOrgSignupRule = signupRuleColumns + `
		  FROM core.signup_rules WHERE org_id = (` + FirstOrgOfIssuer + `)::uuid`

// QueueFirstOrg is FirstOrgOfIssuer as one more statement in a batch the caller sends,
// answered as a QueryRow of it is: pgx.ErrNoRows when the instance has none (E.36).
func QueueFirstOrg(b *pgx.Batch, issuer string) func() (string, error) {
	var org string
	err := errors.New("the batch asking for the first organisation was not sent")
	b.Queue(FirstOrgOfIssuer, issuer).QueryRow(func(row pgx.Row) error {
		err = row.Scan(&org)
		return nil
	})
	return func() (string, error) { return org, err }
}

// QueueFirstOrgSignupRule is the first organisation's sign-up rule as one more statement
// in a batch the caller sends, nil when it has none.
func QueueFirstOrgSignupRule(b *pgx.Batch, issuer string) func() (*SignupRule, error) {
	var rule *SignupRule
	err := errors.New("the batch asking for the sign-up rule was not sent")
	b.Queue(FirstOrgSignupRule, issuer).QueryRow(func(row pgx.Row) error {
		rule, err = scanSignupRule(row)
		return nil
	})
	return func() (*SignupRule, error) { return rule, err }
}
