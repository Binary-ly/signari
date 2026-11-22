package main

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/importer"
	"signari.dev/engine/internal/keys"
)

// pskcAssignment is one line of -assignments: which token goes to whom, and the codes
// that show the person holding it has the token the file says.
type pskcAssignment struct {
	serial, person, code, next string
}

// importPSKC gives the tokens of a vendor's file to the people they were handed to. A file
// says a token's seed and nothing about who has it, so a second file says that, and each
// token shows a code as it would to `user assign-otp`: a seed nobody proved would refuse
// its holder at the next sign-in. One that fails is reported and the rest go on, since a
// mistyped code on line 300 should not undo 299 people.
func importPSKC(ctx context.Context, conn *pgx.Conn, orgID, path, keyFile, assignments string, dryRun bool) error {
	if orgID == "" || path == "" || assignments == "" {
		return fmt.Errorf("-org, -file and -assignments are required: the second a CSV of " +
			"serial,person,code[,next-code]")
	}
	var key []byte
	if keyFile != "" {
		raw, err := os.ReadFile(keyFile) // #nosec G304 -- the operator names the file
		if err != nil {
			return err
		}
		if key, err = hex.DecodeString(strings.TrimSpace(string(raw))); err != nil {
			return fmt.Errorf("-key-file is hex: %w", err)
		}
	}
	f, err := os.Open(path) // #nosec G304 -- the operator names the file to import
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tokens, err := importer.ParsePSKC(f, key)
	if err != nil {
		return err
	}
	wanted, err := readPSKCAssignments(assignments)
	if err != nil {
		return err
	}
	bySerial := make(map[string]importer.PSKCToken, len(tokens))
	for _, t := range tokens {
		bySerial[t.Serial] = t
	}
	var root *keys.RootKey
	if !dryRun {
		if root, err = rootKey(); err != nil {
			return err
		}
	}
	assigned, refused := 0, 0
	for _, a := range wanted {
		token, known := bySerial[a.serial]
		err := errors.New("that serial number is not in the file")
		replaced := false
		if known {
			replaced, err = assignPSKCToken(ctx, conn, orgID, token, a, root)
		}
		switch {
		case err != nil:
			refused++
			fmt.Printf("  %s  %s  refused: %v\n", a.serial, a.person, err)
		case dryRun:
			assigned++
			fmt.Printf("  %s  %s  proved\n", a.serial, a.person)
		case replaced:
			assigned++
			fmt.Printf("  %s  %s  assigned, replacing the one they had\n", a.serial, a.person)
		default:
			assigned++
			fmt.Printf("  %s  %s  assigned\n", a.serial, a.person)
		}
	}
	fmt.Printf("\n  %d of %d tokens in the file proved, %d refused\n", assigned, len(tokens), refused)
	if dryRun {
		fmt.Println("  (preview only: nothing was changed; add -apply to do it)")
		return nil
	}
	fmt.Println("\n  Delete the file and its key: the seeds are sealed in the database now, and a")
	fmt.Println("  copy anywhere else is a second token. The codes given here are spent.")
	if refused > 0 {
		return fmt.Errorf("%d tokens were not assigned", refused)
	}
	return nil
}

func assignPSKCToken(ctx context.Context, conn *pgx.Conn, orgID string, token importer.PSKCToken,
	a pskcAssignment, root *keys.RootKey) (bool, error) {

	userID, userOrg, err := oneInOrg(ctx, conn, "users",
		"(email_fold = lower($1) OR username_fold = lower($1))", a.person, orgID, "user")
	if err != nil {
		return false, err
	}
	if token.HOTP && a.next == "" {
		return false, errors.New("a counter-based token shows two codes: code,next-code")
	}
	counter, err := provedOTPCounter(token.Seed, token.HOTP, token.Params, a.code, a.next)
	if err != nil {
		return false, err
	}
	if root == nil {
		return false, nil
	}
	return assignProvedOTP(ctx, conn, userID, userOrg, token.Seed, token.HOTP, token.Params, counter, root, "pskc")
}

func readPSKCAssignments(path string) ([]pskcAssignment, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	var out []pskcAssignment
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading -assignments: %w", err)
		}
		if len(row) < 3 || len(row) > 4 {
			return nil, fmt.Errorf("line %d of -assignments is not serial,person,code[,next-code]", len(out)+1)
		}
		a := pskcAssignment{serial: strings.TrimSpace(row[0]), person: strings.TrimSpace(row[1]), code: strings.TrimSpace(row[2])}
		if len(row) == 4 {
			a.next = strings.TrimSpace(row[3])
		}
		out = append(out, a)
	}
}
