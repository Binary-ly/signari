package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every change to how a person signs in is told to them (5.04).
//
// A credential added, removed or replaced is the event the account's holder
// must hear about on a channel the person who made it may not control: a
// password changed, a factor enrolled or removed, a provider linked. Most of
// these told nobody -- the self-service password change, the forced one, a text
// message number added, a provider linked or unlinked, an administrator's new
// password or address -- while the audit trail recorded each faithfully.
//
// So the guard is derived from the audit trail: every audit.Event literal whose
// type is a credential change must sit in a function that also tells the holder,
// directly or through a function known to queue the notice.
var credentialEvents = map[string]bool{
	"password.changed":               true,
	"account.password_reset":         true,
	"mfa.totp_enrolled":              true,
	"mfa.email_otp_enrolled":         true,
	"mfa.sms_enrolled":               true,
	"mfa.passkey_registered":         true,
	"mfa.passkey_removed":            true,
	"mfa.totp_removed":               true,
	"mfa.email_otp_removed":          true,
	"mfa.sms_removed":                true,
	"mfa.recovery_codes_regenerated": true,
	"mfa.otp_token_assigned":         true,
	"federation.account_linked":      true,
	"federation.account_unlinked":    true,
	"admin.factor_removed":           true,
	"admin.passkey_link_issued":      true,
	"admin.user_updated":             true,
	"user.email_changed":             true,
	"user.password_removed":          true,
}

// noticeCalls tell the holder, or queue the notice in the change's own
// transaction: RemoveFactor and IssuePasskeyLink queue theirs, and the rest are
// the server's notifiers. A function that records the change and leaves the
// telling to the code that calls it, after its commit, passes when every one of
// its callers tells.
var noticeCalls = map[string]bool{
	"notifyAccount": true, "notifyAuthenticatorBound": true, "notifyAuthenticatorRemoved": true,
	"notifyRecovery": true, "announceTOTP": true,
	"EnqueueAccountNotice": true, "RemoveFactor": true, "IssuePasskeyLink": true,
}

// tellsAndCalls reports whether a function body calls a notifier, and which
// functions it calls by name.
func tellsAndCalls(body *ast.BlockStmt) (tells bool, calls map[string]bool) {
	calls = map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			switch fun := c.Fun.(type) {
			case *ast.Ident:
				calls[fun.Name] = true
			case *ast.SelectorExpr:
				calls[fun.Sel.Name] = true
			}
		}
		return true
	})
	for name := range calls {
		tells = tells || noticeCalls[name]
	}
	return tells, calls
}

func TestEveryCredentialChangeTellsTheHolder(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var silent []string
	// Every function by package directory, for the callers of one that leaves
	// the telling to them.
	type fn struct {
		name  string
		tells bool
		calls map[string]bool
	}
	byDir := map[string][]fn{}
	type quiet struct{ event, name, dir, rel string }
	var quiets []quiet
	for _, dir := range []string{"engine/internal", "engine/cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var events []string
				tells, calls := tellsAndCalls(fd.Body)
				byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], fn{fd.Name.Name, tells, calls})
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch v := n.(type) {
					case *ast.CompositeLit:
						sel, ok := v.Type.(*ast.SelectorExpr)
						if !ok || sel.Sel.Name != "Event" {
							return true
						}
						if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "audit" {
							return true
						}
						for _, e := range v.Elts {
							kv, ok := e.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Type" {
								continue
							}
							if lit, ok := kv.Value.(*ast.BasicLit); ok {
								if s, err := strconv.Unquote(lit.Value); err == nil && credentialEvents[s] {
									events = append(events, s)
								}
							}
						}
					}
					return true
				})
				for _, ev := range events {
					seen[ev] = true
					if !tells {
						rel, _ := filepath.Rel(root, path)
						quiets = append(quiets, quiet{ev, fd.Name.Name, filepath.Dir(path), rel})
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range quiets {
		callers, telling := 0, 0
		for _, f := range byDir[q.dir] {
			if f.calls[q.name] && f.name != q.name {
				callers++
				if f.tells {
					telling++
				}
			}
		}
		if callers == 0 || telling < callers {
			silent = append(silent, q.event+" in "+q.name+" ("+q.rel+")")
		}
	}
	sort.Strings(silent)
	for _, s := range silent {
		t.Errorf("%s records a change to how somebody signs in and tells them nothing: "+
			"notify them on every channel (notifyAccount), or queue it in the change's "+
			"transaction (store.EnqueueAccountNotice)", s)
	}
	for ev := range credentialEvents {
		if !seen[ev] {
			t.Errorf("%s is listed as a credential change and nothing audits it under that name; "+
				"the list has drifted from the code", ev)
		}
	}
}
