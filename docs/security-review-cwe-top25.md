# The 2025 CWE Top 25, against this code

MITRE's 2025 list of the most dangerous software weaknesses, each read against the
engine (Go) and the console (PHP), November 2026. The list is MITRE's 2025 Top 25
page; each entry names where it is held, by file and line, or why it does not
apply. Seven of the twenty-five are memory-safety weaknesses, which neither
language can have in code written here.

| Rank | CWE | Here |
|---|---|---|
| 1 | CWE-79 cross-site scripting | Every page is an `html/template` (`engine/internal/pages/pages.go:54`), which escapes by context; the three places that mark text as already safe are each recorded with why (`engine/gosec-baseline.txt:18-20`: an otpauth URI and QR SVG this server makes, and catalogue text whose interpolated values are escaped first). Every page also carries a Content-Security-Policy (`engine/internal/httpapi/securityheaders.go:115`), and the console runs an inline script only when it carries the response's nonce |
| 2 | CWE-89 SQL injection | pgx with bound parameters throughout. gosec's two SQL rules (G201, G202) report nothing (no line for either in `engine/gosec-baseline.txt`). A table name put into a statement comes from a fixed map, never a request. The console's one dynamic setting goes through `set_config` with bind parameters (`admin/app/Http/Middleware/ScopeToOrganisation.php:53`), never `SET` |
| 3 | CWE-352 cross-site request forgery | Every form post is checked against a double-submit token (`checkCSRF`, `engine/internal/httpapi/session.go:78`), and session cookies are `SameSite`. The console's panel runs Laravel's `PreventRequestForgery` in its middleware (`admin/app/Providers/Filament/AdminPanelProvider.php`) |
| 4 | CWE-862 missing authorization | Every Admin API route is registered through one of two helpers that wrap it in the scope check (`engine/internal/adminapi/server.go:229`, `:238`, `auth` at `:746`), and `TestScopeIsEnforcedPerEndpoint` (`engine/internal/adminapi/principal_test.go:59`) holds a token to its scopes. The console reaches the engine's data only through views whose row-level security returns nothing without an organisation |
| 5 | CWE-787 out-of-bounds write | Not in Go or PHP code written here: both check bounds, there is no cgo (no `import "C"`) and no `unsafe` outside tests |
| 6 | CWE-22 path traversal | No route serves a file from a request's path (no `http.FileServer`, `ServeFile` or `http.Dir`). Pages are embedded (`engine/internal/pages/pages.go:65`). Every file the engine opens is named by the operator's own flag or setting, each recorded (`engine/gosec-baseline.txt:23-32`) |
| 7 | CWE-416 use after free | Not possible in managed memory, as for rank 5 |
| 8 | CWE-125 out-of-bounds read | As for rank 5 |
| 9 | CWE-78 OS command injection | Three subprocesses, each an argument vector with no shell: `kadmin` with the operator's realm, principal and keytab (`engine/internal/kerberos/sync.go:99`, recorded at `engine/gosec-baseline.txt:21`), `stty` around a password prompt, and `softhsm2-util` in a test helper package. No request reaches any of them |
| 10 | CWE-94 code injection | Nothing is evaluated: extension is through out-of-process providers over HTTP (ADR-011), with no plugins, embedded expression language or WebAssembly. Sign-in flow and access policy conditions are a fixed vocabulary parsed into structures |
| 11 | CWE-120 buffer copy without checking size | As for rank 5 |
| 12 | CWE-434 unrestricted upload of a dangerous type | Nothing is uploaded, to the engine or the console. A brand's logo is a URL (`engine/internal/adminapi/instances.go:35`), and the console has no file field |
| 13 | CWE-476 NULL pointer dereference | A nil dereference in Go panics, and the engine recovers it per request (`engine/internal/httpapi/recovermw.go:51`), so one request fails and the process stays up. It cannot read or write memory it should not |
| 14 | CWE-121 stack-based buffer overflow | As for rank 5 |
| 15 | CWE-502 deserialization of untrusted data | JSON only, decoded into fixed types, with duplicate keys refused (`engine/internal/jsonstrict/jsonstrict.go:38`); no `encoding/gob`. The console's cache refuses to unserialise any class (`admin/config/cache.php:134`), and its sessions are kept server-side |
| 16 | CWE-122 heap-based buffer overflow | As for rank 5 |
| 17 | CWE-863 incorrect authorization | A token narrowed to named clients, groups or attributes is held to them by one rule (`mayActOnObject`, `engine/internal/adminapi/principal.go:189`), an organisation's token to its organisation (`requireOrg`, `:410`), and a high-value change can be made to wait for a second person ([approvals.md](approvals.md)) |
| 18 | CWE-20 improper input validation | Request bodies are decoded strictly, unknown fields refused, and a protocol parameter given twice is refused rather than one copy chosen (`refuseDuplicateParams`, `engine/internal/httpapi/dupeparams.go:44`) |
| 19 | CWE-284 improper access control | The schema boundary is a GRANT, not a convention: the console's database role has no privilege on `core` at all, and every organisation's table forces row-level security (`TestEveryOrgScopedTableEnforcesTenantIsolation`, `engine/internal/store/rlscompleteness_test.go:33`) |
| 20 | CWE-200 exposure of sensitive information | A failed sign-in says the same whether the account exists, and takes as long: an unknown name is hashed against a dummy (`engine/internal/httpapi/ldapauth.go:329`). Errors name the refusal, never a stack. Metrics live on their own listener (`SIGNARI_METRICS_ADDR`), with labels from closed sets |
| 21 | CWE-306 missing authentication for a critical function | The Admin API has no unauthenticated route, listens on its own address, and refuses to start without TLS unless plaintext is asked for by name |
| 22 | CWE-918 server-side request forgery | Every outbound request goes through one dialler that refuses loopback, private, link-local and metadata addresses however they are spelt, at connect time, after resolution (`engine/internal/safedial/safedial.go:331`; `TestTheDiallerRefusesLoopbackHoweverItIsSpelled`, `safedial_test.go:78`) |
| 23 | CWE-77 command injection | As for rank 9 |
| 24 | CWE-639 authorization bypass through a user-controlled key | An object named in a path is looked up within the caller's organisation, and every `core_v1` view returns only the organisation's rows (`TestNoCoreV1ViewReturnsAnotherTenantsRow`, `engine/internal/store/viewtenancy_test.go:60`) |
| 25 | CWE-770 allocation without limits or throttling | Guesses are reserved against a budget before the hash is spent (`ReserveRate`, `engine/internal/store/ratelimit.go:55`). Bodies are bounded (`http.MaxBytesReader`, 24 calls in `engine/internal/httpapi`), headers have a read deadline (`ReadHeaderTimeout`), and the Admin API has a rate for the listener and one per token |

## How it was done

Each entry was read against the code, not the documentation: the citation is
where it is held. The memory-safety entries were checked by the absence of what
would bring them in (`import "C"`, `unsafe`), not assumed from the language. Where
an entry rests on a guard test, the test is named, so a change that breaks it fails
the build rather than this page going stale.
