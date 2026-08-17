// Command signari is the engine's operator CLI.
//
//	signari migrate bootstrap   roles, schemas, grants  (requires superuser)
//	signari migrate up          tables, policies, views (runs as signari_engine)
//	signari migrate status      what the database is at, and what this binary expects
//	signari verify              the startup gate, runnable on its own
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/adminapi"
	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/doctor"
	"signari.dev/engine/internal/duo"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/httpapi"
	"signari.dev/engine/internal/importer"
	"signari.dev/engine/internal/janitor"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/policy"
	"signari.dev/engine/internal/posture"
	"signari.dev/engine/internal/proxycheck"
	"signari.dev/engine/internal/radius"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/sms"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "signari: %v\n", err)
		os.Exit(1)
	}
}

// twoWordCommands are the groups whose first word is followed by a verb.
//
// A set rather than a chain of comparisons. As a chain it was a list every new
// command group had to be added to, and forgetting -- which happened with
// `scim-source` -- makes the command print the usage text instead of running,
// with no hint that the dispatch is what is wrong.
var twoWordCommands = map[string]bool{
	"migrate": true, "instance": true, "user": true, "client": true, "duo": true,
	"janitor": true, "keys": true, "import": true, "proxy": true,
	"saml": true, "idp": true, "scim": true, "scim-source": true, "brand": true,
	"group": true, "policy": true, "admin-token": true, "radius": true,
	"ssf": true, "registration": true, "export": true, "dir": true, "audit": true, "rac": true,
}

func usage() error {
	fmt.Fprint(os.Stderr, `usage: signari <command> [flags]

commands:
  migrate bootstrap   apply 0001 (roles, schemas, grants) -- needs a superuser DSN
  migrate up          apply 0002+ (tables, policies, views) as signari_engine
  migrate all         bootstrap then up, in one invocation (for containers)
  migrate status      show applied version, pending migrations, live fingerprint
  verify              run the startup schema gate and exit
  instance create     create an instance and its first signing keys
  user create         create a user with a password
  client create       register an OAuth client
  client set-keys     switch a client to private_key_jwt with its public JWKS
  client set-tls      authenticate a client by TLS certificate (RFC 8705)
  janitor once        run one maintenance pass (serve runs this continuously)
  import keycloak     import users and clients from a Keycloak realm export
  import authentik    import users and groups from an authentik dumpdata export
  keys list           show signing keys, their state and when each may advance
  keys rotate         advance the rotation one safe step (run it again later)
  proxy check         prove a forward-auth deployment actually protects the app
  saml add-sp         register a SAML service provider
  saml list           show registered SAML service providers
  idp add             register an external sign-in provider (Google, GitHub, ...)
  idp list            show external sign-in providers
  scim add            register a SCIM provisioning target
  scim list           show provisioning targets
  scim sync           converge targets on this directory (preview unless -apply)
  scim verify         read each target back and report anyone still active
  group create        create a group
  group member        add or remove a member (-remove)
  group release       let a client see group membership
  group list          show groups and their sizes
  policy test         check a policy file (no database needed -- for CI)
  policy apply        install a policy file
  policy show         print the policy in force
  dir add             register a Google Workspace or Entra ID directory source
  dir sync            reconcile users from a directory (preview unless -apply)
  export audit        write the audit trail as CSV, with its chain verified
  registration enable turn on dynamic client registration (RFC 7591)
  registration token  mint an initial access token for registration
  ssf add-stream      register a Shared Signals receiver for CAEP events
  ssf list            show Shared Signals receivers
  radius add-client   register a network device permitted to send Access-Requests
  radius list         show registered RADIUS clients
  admin-token create  mint a scoped, revocable admin API token
  admin-token list    show admin tokens, their scopes and when each was last used
  admin-token revoke  revoke one immediately, with no restart
  doctor              inspect this deployment and report what is wrong with it
  serve               serve the OIDC endpoints

env:
  SIGNARI_ROOT_KEY        base64 of 32 random bytes; wraps stored private key material

flags:
  -dsn string   PostgreSQL connection string (or set SIGNARI_DSN)
  -to int       stop at this version instead of the latest
`)
	return fmt.Errorf("no command given")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	fs := flag.NewFlagSet("signari", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("SIGNARI_DSN"), "PostgreSQL connection string")
	to := fs.Int("to", 0, "stop at this version (0 = latest)")
	issuer := fs.String("issuer", "", "issuer URL, e.g. https://id.example.com")
	name := fs.String("name", "", "instance display name")
	addr := fs.String("addr", ":8080", "listen address for `serve`")
	tlsCert := fs.String("tls-cert", os.Getenv("SIGNARI_TLS_CERT"), "PEM certificate chain; enables HTTPS")
	tlsKey := fs.String("tls-key", os.Getenv("SIGNARI_TLS_KEY"), "PEM private key")
	adminAddr := fs.String("admin-addr", os.Getenv("SIGNARI_ADMIN_ADDR"), "listen address for the admin API (empty = disabled)")
	email := fs.String("email", "", "user email")
	password := fs.String("password", "", "user password")
	clientID := fs.String("client-id", "", "OAuth client_id (settable verbatim, for migration)")
	redirect := fs.String("redirect", "", "registered redirect_uri (exact match)")
	public := fs.Bool("public", false, "register a public client (PKCE, no secret)")
	file := fs.String("file", "", "path to a realm export (import)")
	orgID := fs.String("org", "", "organisation uuid to import into")
	dryRun := fs.Bool("dry-run", false, "report what would be imported and change nothing")
	alg := fs.String("alg", "", "restrict `keys rotate` to one algorithm (default: all in use)")
	promoteNow := fs.Bool("now", false, "promote without waiting for the publication dwell -- key compromise only")
	appURL := fs.String("app", "", "protected application URL, as the browser reaches it (proxy check)")
	origin := fs.String("origin", "", "the application's own address, to test the bypass (proxy check)")
	probePath := fs.String("path", "", "extra path to probe, repeatable as a comma-separated list (proxy check)")
	insecure := fs.Bool("insecure", false, "skip certificate verification (internal CA or self-signed only)")
	entityID := fs.String("entity-id", "", "the service provider's SAML EntityID")
	acsURL := fs.String("acs", "", "AssertionConsumerService URL, matched exactly (https only)")
	nameIDFormat := fs.String("nameid-format", "persistent", "persistent (pairwise), emailAddress or transient")
	sloURL := fs.String("slo", "", "the provider's SingleLogoutService URL (https)")
	spCert := fs.String("sp-cert", "", "path to the provider's signing certificate (PEM), required for single logout")
	wantSignedReq := fs.Bool("want-signed-requests", false,
		"require this provider to sign its AuthnRequests (needs -sp-cert)")
	sloBinding := fs.String("slo-binding", "HTTP-Redirect",
		"binding for the single logout endpoint: HTTP-Redirect or HTTP-POST")
	duoClientID := fs.String("duo-client-id", "", "Duo integration key (20 characters)")
	duoSecret := fs.String("duo-secret", "", "Duo secret key (40 characters)")
	duoAPIHost := fs.String("duo-api-host", "", "api-XXXXXXXX.duosecurity.com")
	duoFailOpen := fs.Bool("duo-fail-open", false,
		"sign users in WITHOUT a second factor when Duo is unreachable")
	duoUsername := fs.String("duo-username", "", "the username this person has in Duo")
	srcSSOURL := fs.String("sso-url", "", "upstream SAML SSO URL (idp add -kind saml)")
	srcUnsolicited := fs.Bool("allow-unsolicited", false,
		"accept IdP-initiated sign-in, which cannot be tied to a request this browser made")
	srcForceAuthn := fs.Bool("force-authn", false,
		"ask the upstream to re-authenticate rather than reuse its session")
	srcSkew := fs.Int("skew", 30, "clock tolerance in seconds, clamped to 300")
	ldapURL := fs.String("ldap-url", "", "ldap:// or ldaps:// URL of the directory")
	ldapBindDN := fs.String("ldap-bind-dn", "", "DN to bind as when reading")
	ldapPassword := fs.String("ldap-password", "", "password for the bind DN")
	ldapBaseDN := fs.String("ldap-base-dn", "", "base DN to search under")
	ldapFlavour := fs.String("ldap-flavour", "openldap", "openldap, ad or freeipa")
	ldapStartTLS := fs.Bool("ldap-start-tls", true, "upgrade a plaintext connection with StartTLS")
	ldapCA := fs.String("ldap-ca", "", "PEM file of roots that verify the directory server")
	dirDomain := fs.String("domain", "", "Google Workspace domain")
	dirImpersonate := fs.String("impersonate", "", "administrator the service account acts as")
	dirTenant := fs.String("tenant", "", "Entra tenant id (read from the credential file)")
	dirFilter := fs.String("filter", "", "user filter: Google query or Entra OData")
	outFile := fs.String("out", "", "write to this file instead of stdout")
	fromDay := fs.String("from", "", "export from this date, YYYY-MM-DD (inclusive)")
	toDay := fs.String("until", "", "export up to this date, YYYY-MM-DD (exclusive)")
	regOpen := fs.Bool("open", false, "allow registration with no initial access token")
	regMax := fs.Int("max-clients", 100, "ceiling on dynamically registered clients")
	regUses := fs.Int("uses", 0, "how many clients this token may create (0 = unlimited)")
	ssfEndpoint := fs.String("endpoint", "", "https URL to push Security Event Tokens to")
	ssfToken := fs.String("receiver-token", "", "bearer token the Shared Signals receiver issued us (optional)")
	ssfEvents := fs.String("events", "", "comma-separated event types the receiver asked for")
	radiusNet := fs.String("network", "", "CIDR the RADIUS device sends from, e.g. 10.0.0.0/24")
	radiusSecret := fs.String("secret", "", "shared secret configured on the RADIUS device")
	tokenScopes := fs.String("scopes", "",
		"comma-separated admin token scopes, e.g. users:write,clients:write")
	tokenExpires := fs.Duration("expires-in", 0,
		"how long an admin token stays valid, e.g. 2160h for 90 days (0 = never)")
	tokenID := fs.String("token-id", "", "admin token uuid to revoke")
	tlsSubjectDN := fs.String("tls-subject-dn", "", "certificate subject DN that must match (RFC 4514)")
	tlsSANDNS := fs.String("tls-san-dns", "", "certificate dNSName that must match")
	tlsSANURI := fs.String("tls-san-uri", "", "certificate URI SAN that must match")
	tlsBound := fs.Bool("tls-bound-tokens", false, "issue certificate-bound access tokens (RFC 8705)")
	brandName := fs.String("brand-name", "", "product name shown on sign-in pages")
	brandLogo := fs.String("brand-logo", "", "https URL of the logo shown above the sign-in form")
	brandSupport := fs.String("brand-support", "", "https URL offered when someone cannot get in")
	brandPrimary := fs.String("brand-primary", "", "button and link colour, hex")
	brandOnPrimary := fs.String("brand-on-primary", "", "text colour ON buttons, hex")
	brandBackground := fs.String("brand-background", "", "page background, hex")
	brandText := fs.String("brand-text", "", "page text colour, hex")
	launchURL := fs.String("launch-url", "",
		"where the application portal sends a user (the app's own login URL). "+
			"Without it the app is listed but cannot be opened")
	logoURL := fs.String("logo-url", "", "https URL of the application's logo, for the portal")
	portalHidden := fs.Bool("portal-hidden", false,
		"keep this client off the application portal")
	spEncCert := fs.String("sp-encryption-cert", "",
		"path to the provider's ENCRYPTION certificate (PEM); assertions are encrypted to it")
	spKeyTransport := fs.String("sp-key-transport", "rsa-oaep-mgf1p",
		"RSA key transport for encrypted assertions: rsa-oaep-mgf1p (universal) or "+
			"rsa-oaep-sha256 (required under FIPS; check the provider supports it)")
	slug := fs.String("slug", "", "short name used in /login/with/<slug>")
	kind := fs.String("kind", "oidc", "oidc, google, github or microsoft")
	extClientID := fs.String("client-id-ext", "", "client id issued by the external provider")
	extSecret := fs.String("client-secret", "", "client secret issued by the external provider")
	allowSignup := fs.Bool("allow-signup", true, "let this provider create new accounts")
	allowLinking := fs.Bool("allow-linking", true, "let users add this provider to an existing account")
	trustEmail := fs.Bool("trust-email-verification", false, "generic OIDC only: believe this provider's email_verified claim")
	baseURL := fs.String("base-url", "", "SCIM base URL of the target application")
	scimToken := fs.String("token", "", "bearer token the SCIM target issued")
	onDeactivate := fs.String("on-deactivate", "deactivate", "deactivate, delete or nothing")
	dryRun2 := fs.Bool("scim-dry-run", false, "register the target in dry-run mode: record, never send")
	groupName := fs.String("group", "", "group name")
	memberEmail := fs.String("email-member", "", "member's email or username")
	removeMember := fs.Bool("remove", false, "remove the member instead of adding")
	racProtocol := fs.String("protocol", "rdp", "rdp, vnc or ssh")
	racHost := fs.String("host", "", "hostname or address of the machine")
	racPort := fs.Int("port", 0, "port (defaults to the protocol's)")
	racUser := fs.String("login", "", "username on the remote machine")
	racPassword := fs.String("login-password", "", "password on the remote machine")
	racRecording := fs.String("recording-path", "", "where guacd writes session recordings")
	declaredBy := fs.String("by", "", "who is declaring an audit checkpoint")
	reason := fs.String("reason", "", "why an audit checkpoint is being declared")
	policyFile := fs.String("policy-file", "", "path to a policy file")
	jwksPath := fs.String("jwks", "", "file containing the client's PUBLIC JWKS")
	onlyGroups := fs.String("only", "", "comma-separated groups to release (default: all)")
	apply := fs.Bool("apply", false, "actually make changes (scim sync defaults to a preview)")

	cmd := args[0]
	rest := args[1:]
	if twoWordCommands[cmd] {
		if len(rest) == 0 {
			return usage()
		}
		cmd, rest = cmd+" "+rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	// `policy test` needs no database either: checking a file before it is
	// deployed is something you do in CI, where there is no database to reach.
	// Both run without a database: checking a file before it is deployed, and
	// drawing one, are things you do in CI where there is no database to reach.
	switch cmd {
	case "policy test":
		return policyTest(*policyFile)
	case "policy graph":
		return policyGraph(*policyFile, *outFile)
	}

	// `brand check` needs no database: it answers "would this palette be
	// readable", which is arithmetic, and an operator should be able to try
	// colours before committing to them.
	if cmd == "brand check" {
		return brandCheck(*brandPrimary, *brandOnPrimary, *brandBackground, *brandText)
	}

	// `proxy check` deliberately runs BEFORE the database is required. It is a
	// black-box prober: it must be runnable from a laptop, from CI, or from
	// outside the network entirely -- which is where an attacker sits, and
	// therefore the only place the answer is meaningful. Needing the database
	// would confine it to the one host where the result matters least.
	if cmd == "proxy check" {
		return proxyCheck(*appURL, *issuer, *origin, *probePath, *insecure)
	}

	if *dsn == "" {
		return fmt.Errorf("no -dsn given and SIGNARI_DSN is unset")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	switch cmd {
	case "migrate bootstrap":
		return up(ctx, conn, migrate.TierBootstrap, *to)
	case "migrate up":
		return up(ctx, conn, migrate.TierCore, *to)
	case "migrate all":
		// One command so the container image needs no shell to chain two.
		// The runtime image is distroless -- there is no /bin/sh to fall back on,
		// and adding one to a security product to save a CLI verb is a bad trade.
		if err := up(ctx, conn, migrate.TierBootstrap, *to); err != nil {
			return err
		}
		return up(ctx, conn, migrate.TierCore, *to)
	case "migrate status":
		return status(ctx, conn)
	case "doctor":
		return doctorCmd(ctx, conn, *issuer)
	case "verify":
		if err := migrate.Verify(ctx, conn); err != nil {
			return err
		}
		fmt.Println("schema ok")
		return nil
	case "instance create":
		return instanceCreate(ctx, conn, *issuer, *name)
	case "user create":
		return userCreate(ctx, conn, *email, *password)
	case "client set-tls":
		return clientSetTLS(ctx, conn, *clientID, *tlsSubjectDN, *tlsSANDNS, *tlsSANURI,
			*spCert, *tlsBound)
	case "client set-keys":
		return clientSetKeys(ctx, conn, *clientID, *jwksPath)
	case "client create":
		return clientCreate(ctx, conn, *clientID, *name, *redirect, *public,
			*launchURL, *logoURL, *portalHidden)
	case "serve":
		return serve(conn, *addr, *tlsCert, *tlsKey, *adminAddr)
	case "janitor once":
		return janitorOnce(ctx, conn)
	case "import authentik":
		return importAuthentik(ctx, conn, *file, *orgID, !*apply)
	case "import keycloak":
		return importKeycloak(ctx, conn, *file, *orgID, *dryRun)
	case "dir add":
		return dirAdd(ctx, conn, *orgID, *kind, *slug, *name, *file, *dirDomain,
			*dirImpersonate, *dirTenant, *dirFilter, *ldapURL, *ldapBindDN,
			*ldapPassword, *ldapBaseDN, *ldapFlavour, *ldapCA, *ldapStartTLS)
	case "dir sync":
		return dirSync(ctx, conn, *slug, *apply)
	case "rac add":
		return racAdd(ctx, conn, *orgID, *slug, *name, *racProtocol, *racHost,
			*racPort, *racUser, *racPassword, *groupName, *racRecording)
	case "rac list":
		return racList(ctx, conn)
	case "audit checkpoint":
		return auditCheckpoint(ctx, conn, *orgID, *declaredBy, *reason)
	case "export audit":
		return exportAudit(ctx, conn, *orgID, *fromDay, *toDay, *outFile)
	case "registration enable":
		return registrationEnable(ctx, conn, *orgID, *regOpen, *regMax, *tokenScopes)
	case "registration token":
		return registrationToken(ctx, conn, *orgID, *name, *regUses, *tokenExpires)
	case "ssf add-stream":
		return ssfAddStream(ctx, conn, *orgID, *clientID, *ssfEndpoint, *ssfToken, *ssfEvents)
	case "ssf list":
		return ssfListStreams(ctx, conn)
	case "radius add-client":
		return radiusAddClient(ctx, conn, *orgID, *name, *radiusNet, *radiusSecret)
	case "radius disable-client":
		return radiusSetClientEnabled(ctx, conn, *name, false)
	case "radius enable-client":
		return radiusSetClientEnabled(ctx, conn, *name, true)
	case "radius list":
		return radiusListClients(ctx, conn)
	case "admin-token create":
		return adminTokenCreate(ctx, conn, *name, *orgID, *tokenScopes, *tokenExpires)
	case "admin-token list":
		return adminTokenList(ctx, conn)
	case "admin-token revoke":
		return adminTokenRevoke(ctx, conn, *tokenID)
	case "keys list":
		return keysList(ctx, conn)
	case "keys rotate":
		return keysRotate(ctx, conn, *alg, *promoteNow)
	case "saml add-sp":
		return samlAddSP(ctx, conn, *orgID, *entityID, *name, *acsURL, *nameIDFormat, *sloURL,
			*spCert, *wantSignedReq, *sloBinding, *spEncCert, *spKeyTransport)
	case "brand set":
		return brandSet(ctx, conn, *issuer, *brandName, *brandLogo, *brandSupport,
			*brandPrimary, *brandOnPrimary, *brandBackground, *brandText)
	case "brand show":
		return brandShow(ctx, conn, *issuer)
	case "saml list":
		return samlListSPs(ctx, conn)
	case "idp add":
		return idpAdd(ctx, conn, *orgID, *slug, *name, *kind, *extClientID, *extSecret,
			*issuer, *allowSignup, *allowLinking, *trustEmail,
			*entityID, *srcSSOURL, *spCert, *nameIDFormat,
			*srcUnsolicited, *srcForceAuthn, *srcSkew)
	case "idp list":
		return idpList(ctx, conn)
	case "scim add":
		return scimAdd(ctx, conn, *orgID, *slug, *name, *baseURL, *scimToken, *onDeactivate, *dryRun2)
	case "duo set":
		return duoSet(ctx, conn, *orgID, *duoClientID, *duoSecret, *duoAPIHost, *duoFailOpen)
	case "duo enroll":
		return duoEnroll(ctx, conn, *orgID, *email, *duoUsername)
	case "duo show":
		return duoShow(ctx, conn)
	case "scim-source add":
		return scimSourceAdd(ctx, conn, *orgID, *slug, *name, *onDeactivate)
	case "scim-source list":
		return scimSourceList(ctx, conn)
	case "scim list":
		return scimList(ctx, conn)
	case "scim sync":
		return scimSync(ctx, conn, *slug, *apply)
	case "scim verify":
		return scimVerify(ctx, conn, *slug)
	case "group create":
		return groupCreate(ctx, conn, *orgID, *groupName, *name)
	case "group member":
		return groupMember(ctx, conn, *orgID, *groupName, *memberEmail, *removeMember)
	case "group release":
		return groupRelease(ctx, conn, *orgID, *clientID, *onlyGroups)
	case "group list":
		return groupList(ctx, conn)
	case "policy apply":
		return policyApply(ctx, conn, *orgID, *policyFile)
	case "policy show":
		return policyShow(ctx, conn, *orgID)
	default:
		return usage()
	}
}

// janitorOnce runs a single maintenance pass and reports it.
//
// `serve` already runs the janitor, so this exists for the cases where that is
// not what you want: a one-shot after an incident, a cron in a deployment that
// runs the engine read-only, or simply seeing what a pass would do. It takes the
// same advisory lock, so running it against a live cluster is safe.
func janitorOnce(ctx context.Context, conn *pgx.Conn) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	pool, err := pgxpool.New(ctx, conn.Config().ConnString())
	if err != nil {
		return fmt.Errorf("creating connection pool: %w", err)
	}
	defer pool.Close()

	st, err := janitor.RunOnce(ctx, pool, log)
	if err != nil {
		return err
	}
	if st.Skipped {
		fmt.Println("janitor: another node holds the lock; nothing done")
		return nil
	}

	fmt.Printf("janitor: swept %d expired session(s), purged %d code(s)\n",
		st.SessionsSwept, st.CodesPurged)
	if len(st.Parked) == 0 {
		return nil
	}
	// Printed to stdout as well as logged: this is the output an operator ran the
	// command to see.
	fmt.Printf("\n%d relying part%s were never told a session ended:\n",
		len(st.Parked), map[bool]string{true: "y", false: "ies"}[len(st.Parked) == 1])
	for _, p := range st.Parked {
		fmt.Printf("  - %s\n", p)
	}
	return nil
}

// loadInstanceKeys is the shared preamble of the keys commands.
func loadInstanceKeys(ctx context.Context, conn *pgx.Conn) (instanceID string, set *keys.Set, root *keys.RootKey, err error) {
	root, err = rootKey()
	if err != nil {
		return "", nil, nil, err
	}
	var issuer string
	if err = conn.QueryRow(ctx,
		`SELECT id::text, issuer FROM core.instances ORDER BY created_at LIMIT 1`).
		Scan(&instanceID, &issuer); err != nil {
		return "", nil, nil, fmt.Errorf("no instance found -- run `signari instance create -issuer …` first: %w", err)
	}
	set, err = keys.LoadSet(ctx, conn, instanceID, root)
	if err != nil {
		return "", nil, nil, fmt.Errorf("loading signing keys: %w", err)
	}
	return instanceID, set, root, nil
}

func keysList(ctx context.Context, conn *pgx.Conn) error {
	_, set, _, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}

	fmt.Printf("%-24s %-8s %-8s %-22s %s\n", "KID", "ALG", "STATE", "PUBLISHED", "NOTE")
	for _, k := range set.Keys() {
		note := ""
		if k.State() == keys.StateNext {
			if ok, wait := set.CanPromote(k); ok {
				note = "ready to promote"
			} else {
				note = fmt.Sprintf("promotable in %s", wait.Round(time.Minute))
			}
		}
		fmt.Printf("%-24s %-8s %-8s %-22s %s\n",
			k.KID(), k.Algorithm(), k.State(),
			k.PublishedAt().UTC().Format(time.RFC3339), note)
	}
	return nil
}

// keysRotate advances the rotation by exactly one safe step, per algorithm.
//
// Rotation is a process, not a button, and the CLI is shaped to say so. Each run
// does whichever step is legal now:
//
//	no `next` key      -> generate one. It is published in the JWKS immediately
//	                      and cannot sign anything.
//	`next` not ripe     -> report how long remains, change nothing.
//	`next` ripe         -> promote it to active and demote the old active to
//	                      passive, in one transaction.
//
// The dwell between step one and step three is the entire safety property. A
// relying party that cached the JWKS before the new key existed will reject
// everything the new key signs, and plenty of them refresh only at boot. Signing
// with a key nobody has fetched is how a routine rotation becomes an outage --
// so the wait is enforced rather than documented.
func keysRotate(ctx context.Context, conn *pgx.Conn, only string, promoteNow bool) error {
	instanceID, set, root, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}

	// Algorithms currently in use. Rotation replaces what exists; it is not the
	// place to introduce a new algorithm.
	algs := set.Algorithms()
	if only != "" {
		algs = []keys.Algorithm{keys.Algorithm(only)}
	}
	if len(algs) == 0 {
		return fmt.Errorf("no active signing keys to rotate")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, a := range algs {
		var next keys.Key
		for _, k := range set.Keys() {
			if k.Algorithm() == a && k.State() == keys.StateNext {
				next = k
				break
			}
		}

		if next == nil {
			generated, err := keys.Generate(keys.NewKID(), a)
			if err != nil {
				return fmt.Errorf("generating %s key: %w", a, err)
			}
			if err := keys.Save(ctx, tx, instanceID, generated, root); err != nil {
				return err
			}
			fmt.Printf("%s: published %s as `next`. Run `signari keys rotate` again after %s to promote it.\n",
				a, generated.KID(), keys.MinPublishBeforeActive)
			continue
		}

		if ok, wait := set.CanPromote(next); !ok {
			if !promoteNow {
				fmt.Printf("%s: %s is published but not promotable for another %s. Nothing changed.\n",
					a, next.KID(), wait.Round(time.Minute))
				continue
			}
			// Deliberately loud. This is correct for a compromised key, where
			// continuing to sign with it is worse than some relying parties
			// failing verification until their JWKS cache expires -- and wrong
			// for anything else.
			fmt.Fprintf(os.Stderr,
				"WARNING: promoting %s %s after only %s of publication. Relying parties whose "+
					"JWKS cache predates this key will REJECT its signatures until they refresh.\n",
				a, next.KID(), (keys.MinPublishBeforeActive - wait).Round(time.Minute))
		}

		// Demote the outgoing key rather than deleting it: tokens it signed are
		// still live, and passive keys stay in the JWKS precisely so those keep
		// verifying. Deleting here would invalidate every unexpired token.
		if current, err := set.Active(a); err == nil {
			demoted, err := keys.WithState(current, keys.StatePassive)
			if err != nil {
				return err
			}
			if err := keys.Save(ctx, tx, instanceID, demoted, root); err != nil {
				return err
			}
			fmt.Printf("%s: demoted %s to passive (still published, so existing tokens verify).\n",
				a, current.KID())
		}

		promoted, err := keys.WithState(next, keys.StateActive)
		if err != nil {
			return err
		}
		if err := keys.Save(ctx, tx, instanceID, promoted, root); err != nil {
			return err
		}
		fmt.Printf("%s: promoted %s to active. It signs from the next restart or config reload.\n",
			a, promoted.KID())
	}

	return tx.Commit(ctx)
}

// rootKey reads the wrapping key for private key material. It is deliberately
// required rather than defaulted: a generated-on-boot root key would silently
// make every restart invalidate every stored signing key.
func rootKey() (*keys.RootKey, error) {
	b64 := os.Getenv("SIGNARI_ROOT_KEY")
	if b64 == "" {
		return nil, fmt.Errorf(
			"SIGNARI_ROOT_KEY is unset (32 random bytes, base64) -- generate one with:\n" +
				"  head -c 32 /dev/urandom | base64")
	}
	return keys.NewRootKeyFromBase64(os.Getenv("SIGNARI_ROOT_KEY_REF"), b64)
}

func instanceCreate(ctx context.Context, conn *pgx.Conn, issuer, name string) error {
	if issuer == "" {
		return fmt.Errorf("-issuer is required")
	}
	if name == "" {
		name = issuer
	}
	root, err := rootKey()
	if err != nil {
		return err
	}

	var id string
	err = conn.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name) VALUES ($1, $2)
		ON CONFLICT (issuer) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id::text`, issuer, name).Scan(&id)
	if err != nil {
		return fmt.Errorf("creating instance: %w", err)
	}
	fmt.Printf("instance %s\n  issuer %s\n", id, issuer)

	// ES256 as the default for new clients, RS256 always available as the
	// universal floor that every relying-party library can verify.
	created, err := keys.Ensure(ctx, conn, id, root, keys.ES256, keys.RS256)
	if err != nil {
		return fmt.Errorf("ensuring signing keys: %w", err)
	}
	for _, k := range created {
		fmt.Printf("  generated %s key %s (%s)\n", k.Algorithm(), k.KID(), k.State())
	}
	if len(created) == 0 {
		fmt.Println("  signing keys already present")
	}
	return nil
}

func serve(conn *pgx.Conn, addr, tlsCert, tlsKey, adminAddr string) error {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The startup gate. A drifted or half-migrated database must fail here, at
	// boot, with a clear message -- not at 3am inside a query.
	if err := migrate.Verify(ctx, conn); err != nil {
		return err
	}

	root, err := rootKey()
	if err != nil {
		return err
	}

	// Which instance to serve.
	//
	// Previously "the oldest one", which is fine with exactly one and silently
	// wrong with more than one -- the server comes up claiming an issuer nobody
	// intended, and every token it mints is audienced to the wrong deployment.
	// It is the kind of failure that looks like a client misconfiguration.
	//
	// So: name it explicitly, or be told what the choices are.
	instanceID, issuer, err := selectInstance(ctx, conn, os.Getenv("SIGNARI_ISSUER"))
	if err != nil {
		return err
	}

	set, err := keys.LoadSet(ctx, conn, instanceID, root)
	if err != nil {
		return fmt.Errorf("loading signing keys: %w", err)
	}

	// Re-read them while serving. Without this the set was fixed at startup,
	// which meant a rotation reached no relying party until every instance was
	// restarted -- and the publish-then-promote design that makes rotation safe
	// never actually published anything.
	go func() {
		t := time.NewTicker(keys.KeyRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := keys.Refresh(ctx, conn, instanceID, root, set); err != nil {
					// Logged, and the current set kept: the keys already loaded
					// are the ones known to work.
					log.Error("refreshing signing keys", "err", err)
				}
			}
		}
	}()

	pool, err := pgxpool.New(ctx, conn.Config().ConnString())
	if err != nil {
		return fmt.Errorf("creating connection pool: %w", err)
	}
	defer pool.Close()

	// Mail is optional to START but never optional to HAVE: without SMTP the log
	// driver keeps account recovery working locally and warns on every send, which
	// is better than a deployment that looks configured and silently sends nothing.
	mailer := buildMailer(log)

	insecureIssuer := os.Getenv("SIGNARI_INSECURE_ISSUER") == "1"
	if insecureIssuer {
		log.Warn("SIGNARI_INSECURE_ISSUER is set: the issuer may be plaintext HTTP. " +
			"Every token, code and client secret in the flow crosses the network readable. " +
			"This must never be set outside local testing.")
	}

	// Legacy issuers this deployment also claims, so tokens minted for clients
	// mid-migration are still accepted by our own userinfo and introspection.
	var aliases []string
	if rows, err := pool.Query(ctx,
		`SELECT issuer FROM core.instance_issuer_aliases WHERE instance_id = $1::uuid
		   AND (retire_after IS NULL OR retire_after > now())`, instanceID); err == nil {
		for rows.Next() {
			var a string
			if rows.Scan(&a) == nil {
				aliases = append(aliases, a)
			}
		}
		rows.Close()
		if len(aliases) > 0 {
			log.Info("accepting legacy issuer aliases for migrated clients", "aliases", aliases)
		}
	} else {
		log.Error("loading issuer aliases", "err", err)
	}

	// The SMS gateway. A configuration error is FATAL rather than a fallback to
	// no SMS: a deployment that named a gateway has stated an intention, and
	// quietly ignoring a typo is how a second factor turns out to have been
	// undeliverable for a month.
	texter, err := sms.NewFromEnv(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuring the SMS gateway: %w", err)
	}
	if texter != nil {
		log.Info("SMS second factor available", "gateway", texter.Describe())
	}

	srv, err := httpapi.New(oidc.Config{
		Issuer:              issuer,
		IssuerAliases:       aliases,
		ProxyCookieDomain:   os.Getenv("SIGNARI_PROXY_COOKIE_DOMAIN"),
		Keys:                set,
		Root:                root,
		AllowInsecureIssuer: insecureIssuer,
	}, pool, log, mailer, texter)
	if err != nil {
		return err
	}
	// The authorities that may issue client certificates, for RFC 8705. Supplied
	// here because this is where TLS is configured; nil is a valid answer and
	// means tls_client_auth is refused.
	srv.SetClientCAs(clientCAPool())
	pst, perr := postureFromEnv()
	if perr != nil {
		return perr
	}
	srv.SetPosture(pst)

	// The outbox worker is a SINGLETON: running it on every node would deliver
	// each logout notice once per node. It claims rows FOR UPDATE SKIP LOCKED so
	// a second worker started by mistake divides the work rather than duplicating
	// it, but the intent is one.
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go outbox.New(pool, set, issuer, root, log).Run(workerCtx, 2*time.Second)

	// The janitor is likewise a singleton, but it enforces that itself with an
	// advisory lock rather than by convention -- so it is safe to start on every
	// node, and there is no separate unit an operator can forget to deploy. The
	// jobs it runs are the ones whose absence is invisible until it matters:
	// relying parties never told a session ended, and a table that only grows.
	go janitor.Run(workerCtx, pool, log, janitor.DefaultInterval)

	// The admin API listens on its OWN address, and is off unless one is given.
	// It is the write surface for the entire identity provider; exposing it on
	// the same public listener as the protocol endpoints would put it one
	// misconfigured route away from the internet. Bind it to a private interface.
	if adminAddr != "" {
		adminToken := os.Getenv("SIGNARI_ADMIN_TOKEN")
		adminSrv, err := adminapi.New(pool, log, adminToken)
		if err != nil {
			return fmt.Errorf("admin API: %w", err)
		}
		go func() {
			log.Info("admin API listening", "addr", adminAddr)
			ah := &http.Server{
				Addr:              adminAddr,
				Handler:           adminSrv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := ah.ListenAndServe(); err != nil {
				log.Error("admin API stopped", "err", err)
			}
		}()
	}

	// The LDAP shim, for applications that can only authenticate by binding to a
	// directory. Off unless an address is given: it is a second authentication
	// surface, and one nobody asked for should not be listening.
	if ldapAddr := os.Getenv("SIGNARI_LDAP_ADDR"); ldapAddr != "" {
		// ONE organisation per listener, and it is named explicitly.
		//
		// LDAP has no way to express which tenant a bind belongs to -- the DN is
		// the only input, and it is chosen by the client. Serving several
		// organisations from one port would mean inferring the tenant from
		// attacker-controlled data, and inferring it wrong means binding somebody
		// against another organisation's directory.
		//
		// So: stated, not derived. The single-organisation case is filled in
		// automatically because there is nothing to be ambiguous about.
		ldapOrgID := os.Getenv("SIGNARI_LDAP_ORG_ID")
		if ldapOrgID == "" {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM core.organizations`).Scan(&n); err != nil {
				return fmt.Errorf("counting organisations for the LDAP listener: %w", err)
			}
			if n != 1 {
				return fmt.Errorf("SIGNARI_LDAP_ORG_ID is not set and this database holds "+
					"%d organisations. An LDAP listener serves exactly one, and which one "+
					"cannot be inferred from a bind DN the client chose", n)
			}
			if err := pool.QueryRow(ctx, `SELECT id::text FROM core.organizations`).Scan(&ldapOrgID); err != nil {
				return fmt.Errorf("resolving the organisation for the LDAP listener: %w", err)
			}
		}
		baseDN := os.Getenv("SIGNARI_LDAP_BASE_DN")
		if baseDN == "" {
			return fmt.Errorf("SIGNARI_LDAP_ADDR is set but SIGNARI_LDAP_BASE_DN is not; " +
				"the base DN is what every bind DN must sit under and there is no safe default")
		}
		ldapSrv := ldapd.New(ldapd.Config{
			BaseDN:   baseDN,
			UserAttr: envOr("SIGNARI_LDAP_USER_ATTR", "uid"),
			// Anonymous search stays off unless asked for: it publishes a user
			// directory to anyone who can reach the port.
			AllowAnonymousSearch: os.Getenv("SIGNARI_LDAP_ANONYMOUS_SEARCH") == "1",
		}, httpapi.NewLDAPAuthenticator(pool,
			passwords.NewHasher(passwords.MemoryBudgetMiB), ldapOrgID), log)

		ln, err := net.Listen("tcp", ldapAddr)
		if err != nil {
			return fmt.Errorf("LDAP listener: %w", err)
		}
		if tlsCert == "" {
			log.Warn("LDAP is listening WITHOUT TLS: every bind sends a password in the " +
				"clear. Supply -tls-cert and -tls-key, or restrict this listener to a " +
				"trusted network.")
		} else {
			cert, cerr := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if cerr != nil {
				return fmt.Errorf("LDAP TLS: %w", cerr)
			}
			ln = tls.NewListener(ln, &tls.Config{
				Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			})
		}
		go func() {
			log.Info("LDAP listening", "addr", ldapAddr, "base_dn", baseDN, "tls", tlsCert != "")
			if err := ldapSrv.Serve(ctx, ln); err != nil {
				log.Error("LDAP stopped", "err", err)
			}
		}()
	}

	// # RADIUS
	//
	// This listener did not exist. internal/radius was complete, tested against
	// CVE-2024-3596, and imported by nothing -- so `signari serve` had no way to
	// answer an Access-Request, while the roadmap recorded RADIUS as done. Every
	// test passed throughout, because tests prove a package behaves and say
	// nothing about whether anything calls it.
	if radiusAddr := os.Getenv("SIGNARI_RADIUS_ADDR"); radiusAddr != "" {
		radiusOrgID := os.Getenv("SIGNARI_RADIUS_ORG_ID")
		if radiusOrgID == "" {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM core.organizations`).Scan(&n); err != nil {
				return fmt.Errorf("counting organisations for the RADIUS listener: %w", err)
			}
			if n != 1 {
				return fmt.Errorf("SIGNARI_RADIUS_ORG_ID is not set and this database holds "+
					"%d organisations. A RADIUS listener serves exactly one, and a user "+
					"name arriving from a switch does not say which", n)
			}
			if err := pool.QueryRow(ctx, `SELECT id::text FROM core.organizations`).Scan(&radiusOrgID); err != nil {
				return fmt.Errorf("resolving the organisation for the RADIUS listener: %w", err)
			}
		}

		root, rerr := rootKey()
		if rerr != nil {
			return fmt.Errorf("RADIUS shared secrets are sealed with the root key: %w", rerr)
		}
		clients, cerr := loadRADIUSClients(ctx, pool, radiusOrgID, root)
		if cerr != nil {
			return cerr
		}

		// radius.New refuses an empty client list, and that refusal is the point:
		// a server that trusts everybody is an authentication oracle for the whole
		// network. Surfaced here with the command that fixes it rather than as a
		// bare error from a package the operator has never heard of.
		// EAP-TLS, when the deployment has configured a server certificate and
		// the authorities that issue supplicant certificates. Absent, the
		// listener answers password requests only and refuses EAP outright
		// rather than offering something weaker.
		eapCfg, eerr := eapTLSFromEnv(pool, radiusOrgID)
		if eerr != nil {
			return fmt.Errorf("configuring EAP-TLS: %w", eerr)
		}

		radiusSrv, rerr2 := radius.New(radius.Config{Clients: clients, EAPTLS: eapCfg},
			httpapi.NewRADIUSAuthenticator(pool,
				passwords.NewHasher(passwords.MemoryBudgetMiB), radiusOrgID), log)
		if rerr2 != nil {
			return fmt.Errorf("%w -- register one with `signari radius add-client`", rerr2)
		}

		// Re-read the devices while serving. Without this, disabling an access
		// point did nothing until a restart: the listener kept answering a
		// device whose access had been revoked.
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					next, lerr := loadRADIUSClients(ctx, pool, radiusOrgID, root)
					if lerr != nil {
						log.Error("reloading RADIUS clients", "err", lerr)
						continue
					}
					if rerr := radiusSrv.ReplaceClients(next); rerr != nil {
						log.Error("refusing a RADIUS client reload", "err", rerr)
					}
				}
			}
		}()

		pc, perr := net.ListenPacket("udp", radiusAddr)
		if perr != nil {
			return fmt.Errorf("RADIUS listener: %w", perr)
		}
		go func() {
			log.Info("RADIUS listening", "addr", radiusAddr, "clients", len(clients),
				"org_id", radiusOrgID, "eap_tls", eapCfg != nil)
			if err := radiusSrv.Serve(ctx, pc); err != nil {
				log.Error("RADIUS stopped", "err", err)
			}
		}()
	}

	h := &http.Server{
		Addr:    addr,
		Handler: srv.Routes(),
		// A slow-header attack costs an attacker nothing and holds a connection
		// open indefinitely without this.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if tlsCert == "" || tlsKey == "" {
		log.Info("serving over plaintext HTTP", "addr", addr, "issuer", issuer,
			"algs", set.Algorithms())
		log.Warn("no TLS configured: browsers will refuse to store the __Host- session " +
			"cookie over plaintext on any host except localhost, so sign-in will silently " +
			"fail to persist. Supply -tls-cert and -tls-key outside local testing.")
		return h.ListenAndServe()
	}

	// TLS 1.2 floor. 1.0 and 1.1 are deprecated and their cipher suites are not
	// worth the compatibility they buy for a service whose whole job is secrets.
	h.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Request a certificate; verify nothing here.
		//
		// RequireAndVerifyClientCert would demand one from browsers and take the
		// sign-in surface down. VerifyClientCertIfGiven looks right and is worse:
		// with a CA pool it kills self-signed clients during the handshake, and
		// with NO pool it rejects every offered certificate outright -- which
		// breaks self_signed_tls_client_auth, the method that exists because
		// there is no CA.
		//
		// So the chain check moves into clientauth.VerifyClientCertificate, where
		// it can depend on which method the client actually registered. Both
		// methods then work on one listener.
		ClientAuth: tls.RequestClientCert,
		// Go picks sane defaults for TLS 1.3; this constrains 1.2 to suites with
		// forward secrecy and AEAD only.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	log.Info("serving over HTTPS", "addr", addr, "issuer", issuer, "algs", set.Algorithms())
	return h.ListenAndServeTLS(tlsCert, tlsKey)
}

func up(ctx context.Context, conn *pgx.Conn, tier migrate.Tier, to int) error {
	applied, err := migrate.Up(ctx, conn, tier, to)
	// Report what did land even when a later migration fails -- knowing where it
	// stopped is the difference between a five-minute fix and a restore.
	for _, m := range applied {
		fmt.Printf("applied %04d_%s\n", m.Version, m.Name)
	}
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("nothing to apply")
	}
	return nil
}

func status(ctx context.Context, conn *pgx.Conn) error {
	all, err := migrate.Load()
	if err != nil {
		return err
	}
	current, err := migrate.Applied(ctx, conn)
	if err != nil {
		return err
	}

	fmt.Printf("database version : %d\n", current)
	fmt.Printf("binary expects   : %d\n", all[len(all)-1].Version)

	if current > 0 {
		fp, err := migrate.Fingerprint(ctx, conn)
		if err != nil {
			return err
		}
		fmt.Printf("live fingerprint : %s\n", fp)
	}

	var pending []migrate.Migration
	for _, m := range all {
		if m.Version > current {
			pending = append(pending, m)
		}
	}
	if len(pending) == 0 {
		fmt.Println("pending          : none")
		return nil
	}
	fmt.Println("pending          :")
	for _, m := range pending {
		tier := "core"
		if m.Tier() == migrate.TierBootstrap {
			tier = "bootstrap (superuser)"
		}
		fmt.Printf("  %04d_%-24s %s\n", m.Version, m.Name, tier)
	}
	return nil
}

// firstOrg returns the only organisation, creating a default one if the instance
// has none. Development convenience; the admin API owns this in production.
func firstOrg(ctx context.Context, conn *pgx.Conn) (string, error) {
	var orgID string
	err := conn.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&orgID)
	if err == nil {
		return orgID, nil
	}
	var instanceID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.instances ORDER BY created_at LIMIT 1`).Scan(&instanceID); err != nil {
		return "", fmt.Errorf("no instance -- run `signari instance create` first: %w", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1, 'default', 'Default') RETURNING id::text`, instanceID).Scan(&orgID); err != nil {
		return "", err
	}
	return orgID, nil
}

func userCreate(ctx context.Context, conn *pgx.Conn, email, password string) error {
	if email == "" || password == "" {
		return fmt.Errorf("-email and -password are both required")
	}
	orgID, err := firstOrg(ctx, conn)
	if err != nil {
		return err
	}

	// 64 random bytes, stable for the life of the account. This is the WebAuthn
	// user handle and it must never be the email or a sequential id: it is sent
	// to authenticators and stored on the user's device essentially forever.
	handle := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, handle); err != nil {
		return err
	}

	hasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return err
	}

	var userID string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, $2, $3) RETURNING id::text`, orgID, handle, email).Scan(&userID); err != nil {
		return fmt.Errorf("creating user: %w", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1, $2, $3, 'argon2id')`, userID, orgID, hash); err != nil {
		return fmt.Errorf("storing credential: %w", err)
	}
	fmt.Printf("user %s\n  email %s\n", userID, email)
	return nil
}

func clientCreate(ctx context.Context, conn *pgx.Conn, clientID, name, redirect string,
	public bool, launchURL, logoURL string, portalHidden bool) error {

	if clientID == "" || redirect == "" {
		return fmt.Errorf("-client-id and -redirect are both required")
	}
	// Checked here as well as by the CHECK constraint, so the message names the
	// flag rather than the column.
	if launchURL != "" && !strings.HasPrefix(launchURL, "https://") &&
		!strings.HasPrefix(launchURL, "http://localhost") &&
		!strings.HasPrefix(launchURL, "http://127.0.0.1") {
		return fmt.Errorf("-launch-url must be https (or localhost for development): "+
			"a portal tile is a link users are invited to trust, and %q is not", launchURL)
	}
	if logoURL != "" && !strings.HasPrefix(logoURL, "https://") {
		return fmt.Errorf("-logo-url must be https: %q would make every portal "+
			"visit a mixed-content warning", logoURL)
	}
	if portalHidden && launchURL != "" {
		return fmt.Errorf("-portal-hidden and -launch-url contradict each other: " +
			"the launch URL exists only for the portal this flag removes it from")
	}
	// The display name is what a user reads on the consent screen while deciding
	// whether to trust an application. The first version accepted -name and
	// inserted the client id in its place, so every client ever created asked
	// for access under a name like "a7f3-crm-prod". Falling back to the id is
	// right when nothing was given; ignoring what was given is not.
	if name == "" {
		name = clientID
	}
	orgID, err := firstOrg(ctx, conn)
	if err != nil {
		return err
	}

	kind, secret, secretHash := "public", "", ""
	if !public {
		kind = "confidential"
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return err
		}
		secret = base64.RawURLEncoding.EncodeToString(b)
		hasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
		if secretHash, err = hasher.Hash(ctx, secret); err != nil {
			return err
		}
	}

	// client_id is settable verbatim so an existing relying party's configuration
	// does not have to change during a migration.
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, scopes,
		                          initiate_login_uri, logo_uri, portal_hidden)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''),
		        ARRAY['openid','profile','email','offline_access'],
		        NULLIF($6,''), NULLIF($7,''), $8)`,
		clientID, orgID, name, kind, secretHash,
		launchURL, logoURL, portalHidden); err != nil {
		return fmt.Errorf("creating client: %w", err)
	}
	if _, err := conn.Exec(ctx,
		`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
		clientID, redirect); err != nil {
		return fmt.Errorf("registering redirect_uri: %w", err)
	}

	fmt.Printf("client %s (%s)\n  redirect_uri %s\n", clientID, kind, redirect)
	if secret != "" {
		fmt.Printf("  client_secret %s\n  (shown once)\n", secret)
	}
	return nil
}

// buildMailer returns an SMTP sender when configured, or the logging driver.
func buildMailer(log *slog.Logger) mail.Sender {
	host := os.Getenv("SIGNARI_SMTP_HOST")
	from := os.Getenv("SIGNARI_MAIL_FROM")
	if host == "" || from == "" {
		log.Warn("no SMTP configured (SIGNARI_SMTP_HOST, SIGNARI_MAIL_FROM): " +
			"account recovery emails will be written to this log instead of sent")
		return mail.NewLogSender(log, "noreply@invalid")
	}
	port := 587
	if p := os.Getenv("SIGNARI_SMTP_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return &mail.SMTPSender{
		Host: host, Port: port,
		Username: os.Getenv("SIGNARI_SMTP_USERNAME"),
		Password: os.Getenv("SIGNARI_SMTP_PASSWORD"),
		FromAddr: from,
		FromName: os.Getenv("SIGNARI_MAIL_FROM_NAME"),
	}
}

// importKeycloak reads a realm export and creates the equivalent users and
// clients.
//
// One transaction, and a --dry-run that changes nothing: an import is run
// against a production directory by someone who wants to know what it will do
// before it does it, and refusing them that is how imports get run blind.
func importKeycloak(ctx context.Context, conn *pgx.Conn, path, orgID string, dryRun bool) error {
	if path == "" || orgID == "" {
		return fmt.Errorf("-file and -org are both required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	realm, err := importer.Parse(f)
	if err != nil {
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	res, err := importer.Import(ctx, tx, orgID, realm,
		passwords.NewHasher(passwords.MemoryBudgetMiB), dryRun)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("DRY RUN -- nothing was written.\n")
	} else if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("realm %q\n  users:   %d created, %d updated, %d skipped\n  clients: %d created, %d skipped\n",
		realm.Realm, res.UsersCreated, res.UsersUpdated, len(res.UsersSkipped),
		res.ClientsCreated, len(res.ClientsSkipped))

	// Skipped entries are PRINTED, never merely counted. A number tells an
	// operator something went wrong; the list tells them who cannot sign in.
	for _, s := range res.UsersSkipped {
		fmt.Printf("  skipped user:   %s\n", s)
	}
	for _, s := range res.ClientsSkipped {
		fmt.Printf("  skipped client: %s\n", s)
	}
	if !dryRun && res.UsersCreated+res.UsersUpdated > 0 {
		fmt.Printf("\nImported users are marked migration_state=pending and keep their Keycloak\n" +
			"password hash. Each one is upgraded to Argon2id on their first sign-in.\n")
	}
	return nil
}

// selectInstance resolves which instance this process serves.
//
// With one instance, no configuration is needed. With several, refusing to guess
// is the whole point: starting up under the wrong issuer produces tokens every
// relying party rejects, and the error surfaces at the client rather than here.
func selectInstance(ctx context.Context, conn *pgx.Conn, want string) (id, issuer string, err error) {
	if want != "" {
		err = conn.QueryRow(ctx,
			`SELECT id::text, issuer FROM core.instances WHERE issuer = $1`, want).Scan(&id, &issuer)
		if err != nil {
			return "", "", fmt.Errorf("no instance with issuer %q -- create it with "+
				"`signari instance create -issuer %s`: %w", want, want, err)
		}
		return id, issuer, nil
	}

	rows, err := conn.Query(ctx,
		`SELECT id::text, issuer FROM core.instances ORDER BY created_at`)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	type inst struct{ id, issuer string }
	var found []inst
	for rows.Next() {
		var i inst
		if err := rows.Scan(&i.id, &i.issuer); err != nil {
			return "", "", err
		}
		found = append(found, i)
	}

	switch len(found) {
	case 0:
		return "", "", fmt.Errorf("no instance found -- run `signari instance create -issuer …` first")
	case 1:
		return found[0].id, found[0].issuer, nil
	default:
		// Capped. A development database accumulates test instances, and printing
		// three hundred of them turns an actionable error into a wall of text
		// nobody reads.
		const show = 10
		var b strings.Builder
		for i, in := range found {
			if i == show {
				fmt.Fprintf(&b, "\n  ... and %d more", len(found)-show)
				break
			}
			fmt.Fprintf(&b, "\n  %s", in.issuer)
		}
		return "", "", fmt.Errorf("this database has %d instances; set SIGNARI_ISSUER to name "+
			"the one to serve. Available:%s", len(found), b.String())
	}
}

// proxyCheck probes a forward-auth deployment and prints what answered.
//
// Exit status is the point of the command: non-zero when anything served
// content to an anonymous request, so it can sit in CI or a deployment script
// and FAIL the deploy. A report nobody reads changes nothing; a failing exit
// code stops the release.
func proxyCheck(app, issuer, origin, extraPaths string, insecure bool) error {
	if app == "" {
		return fmt.Errorf("give -app, the protected application URL as the browser " +
			"reaches it, e.g. -app https://n8n.example.com")
	}
	var paths []string
	for _, p := range strings.Split(extraPaths, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			paths = append(paths, p)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rep, err := proxycheck.Run(ctx, proxycheck.Options{
		BaseURL: app, Issuer: issuer, Origin: origin, Paths: paths, Insecure: insecure,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n  forward-auth check: %s\n\n", app)
	label := map[proxycheck.Status]string{
		proxycheck.Protected: "  ok  ",
		proxycheck.Exposed:   " OPEN ",
		proxycheck.Absent:    "  --  ",
		proxycheck.Unknown:   "  ??  ",
	}
	for _, r := range rep.Results {
		fmt.Printf("  [%s] %-34s %s\n", label[r.Status], r.Probe, r.Detail)
		if r.Fix != "" {
			fmt.Printf("           -> %s\n", wrap(r.Fix, 66, "              "))
		}
	}

	open := rep.Exposed()
	fmt.Printf("\n  %d probes, %d open\n", len(rep.Results), len(open))

	// Never render a verdict on a host that never answered. A mistyped URL
	// otherwise produces a page of "could not tell" and a clean-looking summary,
	// which is the most dangerous output this command could produce.
	if !rep.Reached {
		fmt.Printf("\n  Nothing answered at %s, so nothing here was tested.\n"+
			"  Check the URL, and that this machine can reach it.\n\n", app)
		return fmt.Errorf("the application never answered; this run proves nothing")
	}

	if len(open) > 0 {
		// Named plainly, and named ACCURATELY -- an origin bypass is a different
		// sentence from an unprotected path, and an operator acts on the words.
		fmt.Printf("\n  %s\n\n", summarise(open))
		return fmt.Errorf("%d of %d probes reached the application unauthenticated",
			len(open), len(rep.Results))
	}
	fmt.Printf("\n  No probe reached the application unauthenticated.\n" +
		"  That is evidence, not a guarantee: it covers the paths and methods\n" +
		"  listed above, from where this ran.\n\n")
	return nil
}

// summarise says what was actually found, rather than one sentence stretched
// over every kind of finding.
func summarise(open []proxycheck.Result) string {
	var paths, methods, other int
	for _, r := range open {
		switch {
		case strings.HasPrefix(r.Probe, "unauthenticated GET"):
			paths++
		case strings.HasPrefix(r.Probe, "unauthenticated "):
			methods++
		default:
			other++
		}
	}
	var parts []string
	if paths > 0 {
		parts = append(parts, fmt.Sprintf("%d path(s) served content to an anonymous request", paths))
	}
	if methods > 0 {
		parts = append(parts, fmt.Sprintf("%d method(s) bypassed authentication", methods))
	}
	for _, r := range open {
		if strings.Contains(r.Probe, "direct-to-origin") {
			parts = append(parts, "the application answers directly, so the proxy is optional")
		}
		if strings.Contains(r.Probe, "header injection") {
			parts = append(parts, "a forged identity header was accepted")
		}
	}
	return "Found: " + strings.Join(parts, "; ") + "."
}

// wrap reflows a fix so a long sentence stays readable in a terminal.
func wrap(s string, width int, indent string) string {
	var out strings.Builder
	col := 0
	for _, w := range strings.Fields(s) {
		if col > 0 && col+len(w)+1 > width {
			out.WriteString("\n" + indent)
			col = 0
		} else if col > 0 {
			out.WriteString(" ")
			col++
		}
		out.WriteString(w)
		col += len(w)
	}
	return out.String()
}

// samlAddSP registers a service provider.
//
// The validation here is the same as the authorization endpoint applies to a
// redirect_uri, and for the same reason: the ACS URL is where a signed assertion
// for a real user gets delivered. Checking it at REGISTRATION means a mistake
// surfaces now, with a message about the registration, rather than during
// someone else's integration as an unexplained refusal.
func samlAddSP(ctx context.Context, conn *pgx.Conn, orgID, entityID, name, acs, nameIDFormat,
	slo, certPath string, wantSignedRequests bool, sloBinding, encCertPath,
	keyTransport string) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this service provider belongs to")
	case entityID == "":
		return fmt.Errorf("give -entity-id, the service provider's EntityID")
	case acs == "":
		return fmt.Errorf("give -acs, the AssertionConsumerService URL assertions are POSTed to")
	}
	if !strings.HasPrefix(acs, "https://") {
		return fmt.Errorf("the ACS URL must be https: %q would carry a signed assertion "+
			"for a real user across the network in the clear", acs)
	}
	if strings.Contains(acs, "*") {
		return fmt.Errorf("%q contains a wildcard. ACS URLs are matched exactly, because "+
			"anything looser lets a request steer where the assertion is delivered", acs)
	}
	if name == "" {
		name = entityID
	}
	switch keyTransport {
	case "", saml.KeyTransportMGF1P:
		keyTransport = saml.KeyTransportMGF1P
	case saml.KeyTransportSHA256:
		// Not the default, deliberately. Every service provider implements
		// mgf1p; xmlenc11 rsa-oaep is widely but not universally supported, and
		// choosing it for one that cannot read it produces assertions that
		// decrypt nowhere.
		if encCertPath == "" {
			return fmt.Errorf("-sp-key-transport only affects encrypted assertions, " +
				"and no -sp-encryption-cert was given, so nothing would be encrypted")
		}
	default:
		return fmt.Errorf("unknown key transport %q: use rsa-oaep-mgf1p or "+
			"rsa-oaep-sha256", keyTransport)
	}
	switch nameIDFormat {
	case "", "persistent":
		nameIDFormat = "persistent"
	case "emailAddress", "transient":
	default:
		return fmt.Errorf("unknown NameID format %q: use persistent, emailAddress or transient",
			nameIDFormat)
	}

	// Single logout needs BOTH a place to send to and a certificate to verify
	// with. A provider configured with a logout URL and no certificate is the
	// dangerous half-configuration: it looks set up, and the endpoint refuses
	// every request because there is nothing to check the signature against.
	var certPEM string
	if certPath != "" {
		b, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("reading the service provider certificate: %w", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return fmt.Errorf("%s is not PEM. Export the provider's SIGNING certificate, "+
				"not its private key or metadata", certPath)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("%s did not parse as a certificate: %w", certPath, err)
		}
		certPEM = string(b)
	}
	if slo != "" && certPEM == "" {
		return fmt.Errorf("a logout URL was given with no -sp-cert. A LogoutRequest is " +
			"acted on only when signed, so without the provider's certificate every " +
			"logout would be refused -- which looks configured and is not")
	}
	if slo != "" && !strings.HasPrefix(slo, "https://") {
		return fmt.Errorf("the logout URL must be https: %q", slo)
	}
	// The ENCRYPTION certificate, which is a different key from the signing one.
	// A provider signs with one and decrypts with another; treating them as
	// interchangeable means either encrypting to a key the provider cannot
	// decrypt with, or encrypting to a key held somewhere it should not be.
	var encCertPEM string
	if encCertPath != "" {
		b, err := os.ReadFile(encCertPath)
		if err != nil {
			return fmt.Errorf("reading the service provider encryption certificate: %w", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return fmt.Errorf("%s is not PEM. Export the provider's ENCRYPTION certificate "+
				"-- in its SAML metadata it is the KeyDescriptor with use=\"encryption\"",
				encCertPath)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%s did not parse as a certificate: %w", encCertPath, err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s holds a %T key; assertion encryption here needs RSA",
				encCertPath, cert.PublicKey)
		}
		if pub.N.BitLen() < 2048 {
			return fmt.Errorf("%s is a %d-bit RSA key; 2048 is the minimum",
				encCertPath, pub.N.BitLen())
		}
		// Caught at registration rather than at first login. The same file given
		// for both is the mistake this separation exists to prevent, and it is
		// silent otherwise: assertions encrypt fine and the provider cannot read
		// a single one.
		if certPEM != "" && strings.TrimSpace(string(b)) == strings.TrimSpace(certPEM) {
			return fmt.Errorf("the signing and encryption certificates are the same file. " +
				"Service providers use separate keys for the two")
		}
		encCertPEM = string(b)
	}

	// The binding is stored because it decides how the LogoutResponse is sent
	// back. Getting it wrong means the provider receives a form POST where it
	// expects query parameters, or the reverse -- it parses nothing and reports a
	// logout failure for a session that was in fact ended.
	switch sloBinding {
	case "HTTP-Redirect", "HTTP-POST":
	default:
		return fmt.Errorf("unknown -slo-binding %q: use HTTP-Redirect or HTTP-POST", sloBinding)
	}
	// The same fail-closed rule as the logout URL, for the same reason. Requiring
	// signed AuthnRequests with no certificate to verify them against means every
	// login is refused: configured-looking and completely broken.
	if wantSignedRequests && certPEM == "" {
		return fmt.Errorf("-want-signed-requests was given with no -sp-cert. There would " +
			"be nothing to verify a signature against, so every AuthnRequest from this " +
			"provider would be refused and nobody could sign in through it")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name, name_id_format,
		                                 sp_signing_cert, want_authn_requests_signed,
		                                 sp_encryption_cert, sp_key_transport)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5,''), $6, NULLIF($7,''), $8)
		RETURNING id::text`, orgID, entityID, name, nameIDFormat, certPEM,
		wantSignedRequests, encCertPEM, keyTransport).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a service provider with entity id %q is already registered "+
				"in that organisation", entityID)
		}
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
		VALUES ($1::uuid, $2, 'HTTP-POST', true)`, id, acs); err != nil {
		return err
	}
	if slo != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.saml_slo_urls (provider_id, url, binding)
			VALUES ($1::uuid, $2, $3)`, id, slo, sloBinding); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("registered %s\n  entity id : %s\n  ACS       : %s\n  NameID    : %s\n",
		name, entityID, acs, nameIDFormat)
	if nameIDFormat == "persistent" {
		fmt.Println("\n  The NameID is pairwise: this service provider sees an opaque identifier\n" +
			"  that no other provider can correlate, and it survives an email change.")
	}
	if encCertPEM != "" {
		fmt.Println("  assertion : encrypted to the certificate given (AES-256-GCM,\n" +
			"              RSA-OAEP key transport)")
	}
	if wantSignedRequests {
		fmt.Println("  requests  : must be signed -- an unsigned AuthnRequest from this\n" +
			"              provider is refused, on both bindings")
	}
	if slo != "" {
		fmt.Printf("  logout    : %s on %s (signature verified against the certificate given)\n",
			slo, sloBinding)
	} else {
		fmt.Println("  logout    : not configured -- single logout is unavailable for this provider")
	}
	fmt.Println("\n  Point the service provider at /saml/metadata to import the certificate.")
	return nil
}

// samlListSPs shows what is registered.
func samlListSPs(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT p.entity_id, p.display_name, p.name_id_format, p.enabled,
		       COALESCE(string_agg(a.url, ', ' ORDER BY a.url), '(none)')
		FROM core.saml_providers p
		LEFT JOIN core.saml_acs_urls a ON a.provider_id = p.id
		GROUP BY p.id, p.entity_id, p.display_name, p.name_id_format, p.enabled
		ORDER BY p.display_name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-38s %-12s %-8s %s\n", "ENTITY ID", "NAMEID", "ENABLED", "ACS")
	var n int
	for rows.Next() {
		var entity, name, format, acs string
		var enabled bool
		if err := rows.Scan(&entity, &name, &format, &enabled, &acs); err != nil {
			return err
		}
		n++
		fmt.Printf("%-38s %-12s %-8t %s\n", truncateMiddle(entity, 38), format, enabled, acs)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari saml add-sp`)")
	}
	return rows.Err()
}

func truncateMiddle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	half := (n - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

// idpAdd registers an external identity provider.
func idpAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name, kind, clientID, secret,
	issuer string, allowSignup, allowLinking, trustEmail bool,
	samlEntityID, samlSSOURL, samlCertPath, samlNameID string,
	samlUnsolicited, samlForceAuthn bool, samlSkew int) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this provider belongs to")
	case slug == "":
		return fmt.Errorf("give -slug, the short name used in the URL /login/with/<slug>")
	case clientID == "" && kind != "saml":
		return fmt.Errorf("give -client-id, issued by the provider")
	}

	// A SAML upstream has no client ID, no scopes and no discovery document. It
	// shares the linking rules with the OAuth kinds and nothing else, so it
	// takes its own path here and rejoins them at the same table.
	if kind == "saml" {
		return idpAddSAML(ctx, conn, orgID, slug, name, samlEntityID, samlSSOURL,
			samlCertPath, samlNameID, allowSignup, allowLinking, trustEmail,
			samlUnsolicited, samlForceAuthn, samlSkew)
	}

	preset, err := federation.PresetFor(federation.Kind(kind))
	if err != nil {
		return err
	}
	// A generic provider is discovered NOW, so a wrong issuer fails in front of
	// the person who typed it rather than at somebody's first sign-in.
	var authorizeURL, tokenURL, userinfoURL, jwksURL string
	if kind == "oidc" {
		if issuer == "" {
			return fmt.Errorf("a generic OIDC provider needs -issuer, so its endpoints " +
				"and signing keys can be discovered")
		}
		d, derr := federation.Discover(ctx, &http.Client{Timeout: 15 * time.Second}, issuer)
		if derr != nil {
			return fmt.Errorf("discovering %s: %w", issuer, derr)
		}
		authorizeURL, tokenURL, userinfoURL, jwksURL = d.AuthorizeURL, d.TokenURL, d.UserinfoURL, d.JWKSURL
		fmt.Printf("discovered %s\n  authorize : %s\n  token     : %s\n  jwks      : %s\n\n",
			issuer, authorizeURL, tokenURL, jwksURL)
	}
	if name == "" {
		name = slug
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	var sealed []byte
	if secret != "" {
		if sealed, err = root.Seal([]byte(secret), "idp_client_secret"); err != nil {
			return fmt.Errorf("sealing the client secret: %w", err)
		}
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.identity_providers
			(org_id, slug, display_name, kind, client_id, client_secret, issuer,
			 authorize_url, token_url, userinfo_url, jwks_url,
			 scopes, allow_signup, allow_linking, trust_email_verification)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, NULLIF($7,''),
		        NULLIF($8,''), NULLIF($9,''), NULLIF($10,''), NULLIF($11,''),
		        $12, $13, $14, $15)`,
		orgID, slug, name, kind, clientID, sealed, issuer,
		authorizeURL, tokenURL, userinfoURL, jwksURL,
		preset.Scopes, allowSignup, allowLinking, trustEmail && kind == "oidc"); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a provider with slug %q is already registered in that "+
				"organisation", slug)
		}
		return err
	}

	fmt.Printf("registered %s (%s)\n", name, kind)
	fmt.Printf("  sign-in URL  : /login/with/%s\n", slug)
	fmt.Printf("  callback URL : <issuer>/login/callback/%s\n", slug)
	fmt.Print("     register that callback with the provider, exactly as written\n")
	fmt.Printf("  scopes       : %s\n", strings.Join(preset.Scopes, " "))

	// The email-verification policy is the part an operator most needs told,
	// because it decides whether sign-up works at all and there is no way to
	// discover it from the provider's own console.
	fmt.Print("\n  Email verification: ")
	switch {
	case preset.TrustsEmailVerification && preset.EmailNeedsSeparateCheck:
		fmt.Printf("established by an extra check.\n    %s\n", preset.Note)
	case preset.TrustsEmailVerification:
		fmt.Printf("trusted as returned.\n    %s\n", preset.Note)
	case kind == "oidc" && trustEmail:
		fmt.Print("trusted, because you passed -trust-email-verification.\n" +
			"    Signari cannot check that claim for an unknown provider. If this one\n" +
			"    does not actually verify addresses, anyone who can register there\n" +
			"    with somebody else's address can create an account here as them.\n")
	default:
		fmt.Printf("NOT trusted.\n    %s\n", preset.Note)
		fmt.Print("    This provider can link to existing accounts but cannot create\n" +
			"    new ones until verification can be established.\n")
	}
	fmt.Printf("\n  Accounts are matched on the provider's subject identifier only.\n"+
		"  A matching email address never links an account -- the user signs in\n"+
		"  locally first and adds the provider from /account/link/%s.\n", slug)
	return nil
}

// idpList shows configured providers.
func idpList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT slug, display_name, kind, allow_signup, allow_linking, enabled,
		       (SELECT count(*) FROM core.federated_identities f WHERE f.provider_id = p.id)
		FROM core.identity_providers p ORDER BY slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-14s %-12s %-8s %-8s %-8s %s\n",
		"SLUG", "KIND", "SIGNUP", "LINKING", "ENABLED", "LINKED ACCOUNTS")
	var n int
	for rows.Next() {
		var slug, name, kind string
		var signup, linking, enabled bool
		var linked int
		if err := rows.Scan(&slug, &name, &kind, &signup, &linking, &enabled, &linked); err != nil {
			return err
		}
		n++
		fmt.Printf("%-14s %-12s %-8t %-8t %-8t %d\n", slug, kind, signup, linking, enabled, linked)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari idp add`)")
	}
	return rows.Err()
}

// scimHTTPClient builds the client used to reach SCIM targets.
//
// SIGNARI_SCIM_CA_BUNDLE adds a certificate authority to the trust store for
// these requests. Internal provisioning targets frequently sit behind a private
// CA, and the alternative operators reach for is disabling verification
// entirely -- so a narrow, explicit way to trust the right CA is offered
// instead of a flag that trusts everything.
//
// It ADDS to the system pool rather than replacing it, so configuring an
// internal CA does not silently stop public targets from verifying.
func scimHTTPClient() (*http.Client, error) {
	bundle := os.Getenv("SIGNARI_SCIM_CA_BUNDLE")
	if bundle == "" {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	pem, err := os.ReadFile(bundle)
	if err != nil {
		return nil, fmt.Errorf("reading SIGNARI_SCIM_CA_BUNDLE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no certificates", bundle)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// scimAdd registers a provisioning target.
func scimAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name, baseURL, token,
	onDeactivate string, dryRun bool) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid")
	case slug == "":
		return fmt.Errorf("give -slug, a short name for this target")
	case baseURL == "":
		return fmt.Errorf("give -base-url, the target's SCIM base URL, e.g. " +
			"https://api.slack.com/scim/v2")
	case token == "":
		return fmt.Errorf("give -token, the bearer token the target issued")
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return fmt.Errorf("the base URL must be https: this token can create and delete " +
			"accounts in that system, and it is sent on every request")
	}
	switch onDeactivate {
	case "deactivate", "delete", "nothing":
	default:
		return fmt.Errorf("-on-deactivate must be deactivate, delete or nothing")
	}
	if name == "" {
		name = slug
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	if err := store.AddSCIMTarget(ctx, conn, root, orgID, slug, name, baseURL, token,
		onDeactivate, dryRun); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a target named %q is already registered", slug)
		}
		return err
	}

	fmt.Printf("registered %s\n  base URL      : %s\n  on deactivate : %s\n  dry run       : %t\n",
		name, baseURL, onDeactivate, dryRun)
	fmt.Println("\n  Nothing is sent until you run `signari scim sync`.")
	fmt.Println("  Run `signari scim verify` afterwards: it reads the target's actual state")
	fmt.Println("  back, which is the only way to know a deactivation really happened.")
	return nil
}

// scimVerify reconciles what each target holds against what it should hold.
//
// The command that makes deprovisioning checkable. Everything else records what
// we MEANT; this asks the target.
func scimVerify(ctx context.Context, conn *pgx.Conn, only string) error {
	root, err := rootKey()
	if err != nil {
		return err
	}
	targets, err := store.LoadSCIMTargets(ctx, conn, root, only)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("no enabled provisioning targets (add one with `signari scim add`)")
		return nil
	}

	var criticals, unreachable, findings int
	for _, t := range targets {
		desired, err := store.SCIMDesiredState(ctx, conn, t)
		if err != nil {
			return err
		}
		var expected []scim.Expected
		for _, d := range desired {
			if d.RemoteID == "" {
				continue // never provisioned; sync's job, not verify's
			}
			expected = append(expected, scim.Expected{
				UserID: d.UserID, RemoteID: d.RemoteID, UserName: d.UserName,
				Active: d.Active, Synced: d.Synced,
			})
		}

		hc, err := scimHTTPClient()
		if err != nil {
			return err
		}
		client := scim.NewClient(t, hc)
		rep, err := scim.Verify(ctx, client, expected, nil)
		if err != nil {
			return err
		}

		fmt.Printf("\n  %s\n", rep.Summary())
		if rep.Unreachable {
			unreachable++
			continue
		}
		for _, f := range rep.Findings {
			fmt.Printf("    [%-8s] %-28s %s\n", f.Severity, f.UserName, f.Summary)
			if f.Severity == scim.Critical {
				fmt.Printf("               -> %s\n", wrap(f.Fix, 62, "                  "))
			}
		}
		criticals += len(rep.CriticalFindings())
		findings += len(rep.Findings)
	}

	fmt.Println()
	switch {
	case criticals > 0:
		// Non-zero exit, so this can gate a deploy or run from cron and be noticed.
		return fmt.Errorf("%d user(s) retain access at a target after being deactivated here",
			criticals)
	case unreachable > 0:
		return fmt.Errorf("%d target(s) could not be reached, so their state is unknown",
			unreachable)
	case findings > 0:
		// Exit 0: nobody has access they should not, which is what this command
		// gates on. But saying "every target agrees" here would be a plain
		// falsehood -- it printed the disagreements four lines earlier.
		fmt.Printf("  %d finding(s), none of them a security problem. "+
			"Nobody has access they should not.\n", findings)
		return nil
	}
	fmt.Println("  Every target agrees with this directory.")
	return nil
}

// scimSync converges each target on the desired state.
func scimSync(ctx context.Context, conn *pgx.Conn, only string, apply bool) error {
	root, err := rootKey()
	if err != nil {
		return err
	}
	targets, err := store.LoadSCIMTargets(ctx, conn, root, only)
	if err != nil {
		return err
	}

	for _, t := range targets {
		desired, err := store.SCIMDesiredState(ctx, conn, t)
		if err != nil {
			return err
		}
		hc, err := scimHTTPClient()
		if err != nil {
			return err
		}
		client := scim.NewClient(t, hc)
		var created, deactivated, deleted, failed int

		for _, d := range desired {
			switch {
			case d.RemoteID == "" && d.Active:
				if !apply {
					created++
					continue
				}
				u := scim.NewUser(d.UserID, d.UserName, d.DisplayName, d.Email, true)
				id, err := client.CreateUser(ctx, u)
				if err != nil {
					// A conflict means the account is already there; find it and
					// record its id rather than creating a duplicate or giving up.
					var se *scim.Error
					if errors.As(err, &se) && se.Conflict {
						if found, ferr := client.FindByUserName(ctx, d.UserName); ferr == nil && found != nil {
							id = found.ID
						}
					}
					if id == "" {
						fmt.Printf("    create %s: %v\n", d.UserName, err)
						failed++
						continue
					}
				}
				if err := store.RecordSCIMLink(ctx, conn, t.ID, d.UserID, t.OrgID, id, true); err != nil {
					return err
				}
				created++

			case d.RemoteID != "" && !d.Active:
				if t.OnDeactivate == "nothing" {
					continue
				}
				if !apply {
					deactivated++
					continue
				}
				if err := store.MarkSCIMIntent(ctx, conn, t.ID, d.UserID, false); err != nil {
					return err
				}
				if t.OnDeactivate == "delete" {
					if err := client.DeleteUser(ctx, d.RemoteID); err != nil {
						fmt.Printf("    delete %s: %v\n", d.UserName, err)
						failed++
						continue
					}
					if err := store.DropSCIMLink(ctx, conn, t.ID, d.UserID); err != nil {
						return err
					}
					deleted++
					continue
				}
				if err := client.SetActive(ctx, d.RemoteID, false); err != nil {
					fmt.Printf("    deactivate %s: %v\n", d.UserName, err)
					failed++
					continue
				}
				if err := store.ConfirmSCIMSync(ctx, conn, t.ID, d.UserID); err != nil {
					return err
				}
				deactivated++
			}
		}

		verb := "would"
		if apply {
			verb = "did"
		}
		fmt.Printf("  %s: %s create %d, deactivate %d, delete %d, failed %d\n",
			t.Slug, verb, created, deactivated, deleted, failed)
	}

	if !apply {
		fmt.Println("\n  Nothing was sent. Re-run with -apply to make these changes.")
		return nil
	}
	fmt.Println("\n  Run `signari scim verify` to confirm the targets agree.")
	return nil
}

// scimList shows configured targets.
func scimList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT t.slug, t.display_name, t.base_url, t.on_deactivate, t.dry_run, t.enabled,
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id),
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id AND NOT l.should_be_active)
		FROM core.scim_targets t ORDER BY t.slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-12s %-38s %-12s %-8s %s\n", "SLUG", "BASE URL", "ON DEACTIVATE", "LINKED", "SHOULD BE GONE")
	var n int
	for rows.Next() {
		var slug, name, base, onDeact string
		var dry, enabled bool
		var linked, inactive int
		if err := rows.Scan(&slug, &name, &base, &onDeact, &dry, &enabled, &linked, &inactive); err != nil {
			return err
		}
		n++
		fmt.Printf("%-12s %-38s %-12s %-8d %d\n", slug, truncateMiddle(base, 38), onDeact, linked, inactive)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari scim add`)")
	}
	return rows.Err()
}

// envOr reads an environment variable with a fallback.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// groupCreate adds a group.
func groupCreate(ctx context.Context, conn *pgx.Conn, orgID, name, displayName string) error {
	if orgID == "" || name == "" {
		return fmt.Errorf("give -org and -name")
	}
	if _, err := store.CreateGroup(ctx, conn, orgID, name, displayName, ""); err != nil {
		if strings.Contains(err.Error(), "groups_name_shape") {
			return fmt.Errorf("%q is not a usable group name. It travels through JSON "+
				"arrays, SAML attribute values and LDAP filters, so it must be letters, "+
				"digits, dot, underscore or hyphen only", name)
		}
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a group named %q already exists in that organisation", name)
		}
		return err
	}
	fmt.Printf("created group %s\n", name)
	fmt.Println("\n  No client sees this group until you release it:")
	fmt.Println("    signari group release -org <uuid> -client-id <id>")
	fmt.Println("  Group membership is authorization data, so release is an allow-list.")
	return nil
}

// groupMember adds or removes a member.
func groupMember(ctx context.Context, conn *pgx.Conn, orgID, name, email string, remove bool) error {
	if orgID == "" || name == "" || email == "" {
		return fmt.Errorf("give -org, -name and -email")
	}
	var userID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.users WHERE org_id = $1::uuid
		   AND (lower(email) = lower($2) OR lower(username) = lower($2))`,
		orgID, email).Scan(&userID); err != nil {
		return fmt.Errorf("no user %q in that organisation", email)
	}

	if remove {
		removed, err := store.RemoveGroupMember(ctx, conn, orgID, name, userID)
		if err != nil {
			return err
		}
		if !removed {
			fmt.Printf("%s was not in %s; nothing to do\n", email, name)
			return nil
		}
		fmt.Printf("removed %s from %s\n", email, name)
		// The honest caveat. Access tokens already issued keep their claims until
		// they expire, and saying so is the difference between an operator who
		// knows to revoke the session and one who assumes the removal was instant.
		fmt.Println("\n  Tokens ALREADY ISSUED still carry this group until they expire.")
		fmt.Println("  New tokens will not: membership is read at issuance, not cached.")
		fmt.Println("  To cut it off now, end their sessions:")
		fmt.Println("    PATCH /admin/users/<id> {\"active\": false}  (then re-activate)")
		return nil
	}

	if err := store.AddGroupMember(ctx, conn, orgID, name, userID, ""); err != nil {
		return err
	}
	fmt.Printf("added %s to %s\n", email, name)
	return nil
}

// groupRelease permits a client to see group membership.
func groupRelease(ctx context.Context, conn *pgx.Conn, orgID, clientID, only string) error {
	if orgID == "" || clientID == "" {
		return fmt.Errorf("give -org and -client-id")
	}
	var onlyGroups []string
	for _, g := range strings.Split(only, ",") {
		if g = strings.TrimSpace(g); g != "" {
			onlyGroups = append(onlyGroups, g)
		}
	}
	if err := store.ReleaseGroupsToClient(ctx, conn, orgID, clientID, onlyGroups); err != nil {
		return err
	}
	if len(onlyGroups) == 0 {
		fmt.Printf("%s may now see ALL group membership\n", clientID)
	} else {
		fmt.Printf("%s may now see only: %s\n", clientID, strings.Join(onlyGroups, ", "))
	}
	fmt.Println("\n  The client must also request the `groups` scope. Both gates apply:")
	fmt.Println("  the scope is asked for by the client, the release is decided by you.")
	return nil
}

// groupList shows groups and their sizes.
func groupList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT g.name, g.display_name,
		       (SELECT count(*) FROM core.group_members m WHERE m.group_id = g.id)
		FROM core.groups g ORDER BY g.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Printf("%-24s %-28s %s\n", "NAME", "DISPLAY NAME", "MEMBERS")
	var n int
	for rows.Next() {
		var name, disp string
		var members int
		if err := rows.Scan(&name, &disp, &members); err != nil {
			return err
		}
		n++
		fmt.Printf("%-24s %-28s %d\n", name, disp, members)
	}
	if n == 0 {
		fmt.Println("(none -- create one with `signari group create`)")
	}
	return rows.Err()
}

// clientSetKeys configures a client for private_key_jwt.
func clientSetKeys(ctx context.Context, conn *pgx.Conn, clientID, jwksPath string) error {
	if clientID == "" || jwksPath == "" {
		return fmt.Errorf("give -client-id and -jwks (a file containing the client's PUBLIC JWKS)")
	}
	raw, err := os.ReadFile(jwksPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", jwksPath, err)
	}

	// Parsed and checked HERE rather than at first use. A key set that turns out
	// to be unusable at 3am, during somebody's first token request, is a much
	// worse discovery than one refused at the moment it is registered.
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("%s is not a JWKS document: %w", jwksPath, err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("%s contains no keys", jwksPath)
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return fmt.Errorf("%s contains PRIVATE key material. Register the public "+
				"half only -- the whole point of private_key_jwt is that we never hold "+
				"anything that can authenticate as this client", jwksPath)
		}
		if !k.Valid() {
			return fmt.Errorf("%s contains a key that is not usable", jwksPath)
		}
	}

	tag, err := conn.Exec(ctx, `
		UPDATE core.clients
		SET token_endpoint_auth_method = 'private_key_jwt', jwks = $2::jsonb,
		    client_secret_hash = NULL, updated_at = now()
		WHERE client_id = $1`, clientID, string(raw))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client with id %q", clientID)
	}

	fmt.Printf("%s now authenticates with private_key_jwt (%d key(s))\n", clientID, len(set.Keys))
	// The secret is dropped, not kept. Leaving it would let an attacker who
	// obtained it keep authenticating -- the exact thing this change retires.
	fmt.Println("\n  The client secret has been REMOVED. It would otherwise remain a")
	fmt.Println("  working credential, which is what moving to keys was meant to end.")
	return nil
}

// policyTest checks a policy file without deploying it.
//
// The same load path the engine uses, so "it passes here" and "it will load"
// are the same statement rather than two things that drift.
func policyTest(path string) error {
	if path == "" {
		return fmt.Errorf("give -policy-file, the policy file to check")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	f, err := policy.Parse(data)
	if err != nil {
		return err
	}
	fmt.Printf("  %s: %s\n", path, f.Summary())
	for _, tc := range f.Tests {
		fmt.Printf("    ok   %s\n", tc.Name)
	}
	fmt.Println("\n  This file will load. Its rules do what its tests say.")
	return nil
}

// policyApply installs a policy file.
func policyApply(ctx context.Context, conn *pgx.Conn, orgID, path string) error {
	if orgID == "" || path == "" {
		return fmt.Errorf("give -org and -policy-file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// Parsed BEFORE storing. A file that would not load must not reach the
	// database, or the next engine start fails on something an operator already
	// believes is deployed.
	f, err := policy.Parse(data)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.access_policies (org_id, document, applied_at)
		VALUES ($1::uuid, $2, now())
		ON CONFLICT (org_id) DO UPDATE
			SET document = EXCLUDED.document, applied_at = now()`,
		orgID, string(data)); err != nil {
		return err
	}
	fmt.Printf("applied %s (%s)\n", path, f.Summary())
	return nil
}

// policyShow prints the policy currently in force.
func policyShow(ctx context.Context, conn *pgx.Conn, orgID string) error {
	var doc string
	var applied time.Time
	if err := conn.QueryRow(ctx,
		`SELECT document, applied_at FROM core.access_policies WHERE org_id = $1::uuid`,
		orgID).Scan(&doc, &applied); err != nil {
		fmt.Println("no policy is in force for that organisation (everything is allowed)")
		return nil
	}
	fmt.Printf("# applied %s\n%s", applied.UTC().Format(time.RFC3339), doc)
	return nil
}

// doctorCmd inspects a deployment and reports what is wrong with it.
//
// Exit status is the point: non-zero when anything critical is found, so it can
// gate a deploy or run from cron. A report nobody reads changes nothing.
func doctorCmd(ctx context.Context, conn *pgx.Conn, issuer string) error {
	if issuer == "" {
		issuer = os.Getenv("SIGNARI_ISSUER")
	}
	rep, err := doctor.Inspect(ctx, conn, issuer)
	if err != nil {
		return err
	}

	fmt.Printf("\n  signari doctor\n\n")
	if len(rep.Findings) == 0 {
		fmt.Println("  Nothing to report.")
	}
	for _, f := range rep.Findings {
		fmt.Printf("  [%-8s] %-14s %s\n", f.Severity, f.Area, f.Summary)
		if f.Severity != doctor.Info {
			fmt.Printf("               -> %s\n", wrap(f.Fix, 62, "                  "))
		}
	}

	// What RAN is printed, always. "No findings" and "nothing ran" have looked
	// identical at least three times in this project's own history, and each
	// time the difference mattered.
	fmt.Printf("\n  checked: %s\n", strings.Join(rep.Checked, ", "))

	crit, warn := rep.Count(doctor.Critical), rep.Count(doctor.Warning)
	fmt.Printf("  %d critical, %d warning, %d info\n\n", crit, warn, rep.Count(doctor.Info))
	if crit > 0 {
		return fmt.Errorf("%d critical finding(s)", crit)
	}
	return nil
}

// adminTokenCreate mints a scoped admin API credential.
//
// The secret is printed once and never stored. Everything about the design
// pushes toward that: the table holds a SHA-256, and there is no command to
// retrieve a token, only to replace one.
func adminTokenCreate(ctx context.Context, conn *pgx.Conn, name, orgID, scopes string,
	expiresIn time.Duration) error {

	if name == "" {
		return fmt.Errorf("give -name; it appears in the audit trail, and \"which token " +
			"was that\" is unanswerable without one")
	}
	var list []string
	for _, sc := range strings.Split(scopes, ",") {
		if sc = strings.TrimSpace(sc); sc != "" {
			list = append(list, sc)
		}
	}
	if len(list) == 0 {
		return fmt.Errorf("give -scopes, comma separated. Known scopes: %s",
			strings.Join(adminapi.KnownScopes, ", "))
	}

	var expires *time.Time
	if expiresIn > 0 {
		t := time.Now().Add(expiresIn)
		expires = &t
	}

	secret, id, err := adminapi.NewToken(ctx, conn, name, orgID, list, expires)
	if err != nil {
		return err
	}

	fmt.Printf("\n  %s\n\n", secret)
	fmt.Printf("  id     : %s\n  name   : %s\n  scopes : %s\n", id, name, strings.Join(list, ", "))
	if orgID == "" {
		fmt.Println("  org    : every organisation")
	} else {
		fmt.Printf("  org    : %s only\n", orgID)
	}
	if expires != nil {
		fmt.Printf("  expires: %s\n", expires.Format(time.RFC3339))
	} else {
		fmt.Println("  expires: never -- consider -expires-in")
	}
	fmt.Println("\n  This is the only time the token is shown. It is stored as a hash,\n" +
		"  so it cannot be recovered -- if it is lost, revoke it and mint another.")
	return nil
}

func adminTokenList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT t.id::text, t.name, COALESCE(o.slug, 'ALL'), t.scopes,
		       t.created_at, t.expires_at, t.revoked_at, t.last_used_at
		FROM core.admin_tokens t
		LEFT JOIN core.organizations o ON o.id = t.org_id
		ORDER BY t.revoked_at NULLS FIRST, t.created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("\n  %-38s %-24s %-12s %s\n", "ID", "NAME", "ORG", "STATE")
	n := 0
	for rows.Next() {
		var id, name, org string
		var scopes []string
		var created time.Time
		var expires, revoked, lastUsed *time.Time
		if err := rows.Scan(&id, &name, &org, &scopes, &created, &expires, &revoked,
			&lastUsed); err != nil {
			return err
		}
		n++

		state := "active"
		switch {
		case revoked != nil:
			state = "revoked"
		case expires != nil && time.Now().After(*expires):
			state = "expired"
		case expires != nil:
			state = "expires " + expires.Format("2006-01-02")
		}
		fmt.Printf("  %-38s %-24s %-12s %s\n", id, truncate(name, 24), truncate(org, 12), state)
		used := "never used"
		if lastUsed != nil {
			used = "last used " + lastUsed.Format("2006-01-02 15:04")
		}
		fmt.Printf("  %-38s %s | %s\n", "", strings.Join(scopes, ","), used)
	}
	if n == 0 {
		fmt.Println("\n  No admin tokens. The API is reachable only with SIGNARI_ADMIN_TOKEN,")
		fmt.Println("  which grants everything in every organisation and cannot be revoked")
		fmt.Println("  without restarting every node.")
	}
	return rows.Err()
}

func adminTokenRevoke(ctx context.Context, conn *pgx.Conn, id string) error {
	if id == "" {
		return fmt.Errorf("give -token-id (see `signari admin-token list`)")
	}
	tag, err := conn.Exec(ctx, `
		UPDATE core.admin_tokens SET revoked_at = now()
		WHERE id = $1::uuid AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Said plainly rather than reported as success. "Revoked" for a token that
		// was never touched is the most dangerous possible false reassurance.
		return fmt.Errorf("no active token with id %s; it does not exist or was already "+
			"revoked -- nothing was changed", id)
	}
	fmt.Printf("revoked %s\n", id)
	fmt.Println("It stops working on the next request. No restart is needed.")
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// radiusAddClient registers a network device permitted to send Access-Requests.
func radiusAddClient(ctx context.Context, conn *pgx.Conn, orgID, name, network, secret string) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this device authenticates against")
	case name == "":
		return fmt.Errorf("give -name; it is what appears in the logs when this device asks")
	case network == "":
		return fmt.Errorf("give -network, the CIDR the device sends from, e.g. 10.0.0.0/24")
	}
	if secret == "" {
		return fmt.Errorf("give -secret, the shared secret configured on the device")
	}
	if err := radius.ValidSecret(secret); err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("-network %q is not a CIDR: %w", network, err)
	}
	if ones, _ := ipnet.Mask.Size(); ones == 0 {
		return fmt.Errorf("-network %q accepts every source address on the internet. "+
			"RADIUS has no handshake and no certificate, so the address range is part "+
			"of the credential -- narrow it to the devices that actually ask", network)
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	sealed, err := root.Seal([]byte(secret), "radius-client-secret")
	if err != nil {
		return fmt.Errorf("sealing the shared secret: %w", err)
	}

	var id string
	err = conn.QueryRow(ctx, `
		INSERT INTO core.radius_clients (org_id, name, network, secret_enc)
		VALUES ($1::uuid, $2, $3::cidr, $4)
		RETURNING id::text`, orgID, name, ipnet.String(), sealed).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a RADIUS client for %s is already registered in that "+
				"organisation; two entries for one range with different secrets is a "+
				"configuration nobody can reason about", ipnet.String())
		}
		return err
	}

	fmt.Printf("registered %s\n  network : %s\n  id      : %s\n", name, ipnet.String(), id)
	fmt.Println("\n  Start the listener with SIGNARI_RADIUS_ADDR (and SIGNARI_RADIUS_ORG_ID\n" +
		"  if this database holds more than one organisation).")
	return nil
}

func radiusListClients(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT c.name, host(c.network) || '/' || masklen(c.network), c.enabled, o.slug
		FROM core.radius_clients c
		JOIN core.organizations o ON o.id = c.org_id
		ORDER BY o.slug, c.name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	n := 0
	fmt.Printf("\n  %-28s %-20s %-10s %s\n", "NAME", "NETWORK", "STATE", "ORG")
	for rows.Next() {
		var name, network, org string
		var enabled bool
		if err := rows.Scan(&name, &network, &enabled, &org); err != nil {
			return err
		}
		n++
		state := "enabled"
		if !enabled {
			state = "disabled"
		}
		fmt.Printf("  %-28s %-20s %-10s %s\n", truncate(name, 28), network, state, org)
	}
	if n == 0 {
		fmt.Println("\n  No RADIUS clients. The listener refuses to start without at least one:")
		fmt.Println("  a server that trusts everybody is an authentication oracle for the")
		fmt.Println("  whole network.")
	}
	return rows.Err()
}

// loadRADIUSClients reads and unseals the configured devices for one organisation.
func loadRADIUSClients(ctx context.Context, pool *pgxpool.Pool, orgID string,
	root *keys.RootKey) ([]radius.Client, error) {

	rows, err := pool.Query(ctx, `
		SELECT name, network, secret_enc FROM core.radius_clients
		WHERE org_id = $1::uuid AND enabled`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []radius.Client
	for rows.Next() {
		var name string
		var network netip.Prefix
		var sealed []byte
		if err := rows.Scan(&name, &network, &sealed); err != nil {
			return nil, err
		}
		secret, err := root.Open(sealed, "radius-client-secret")
		if err != nil {
			return nil, fmt.Errorf("unsealing the secret for RADIUS client %q: %w", name, err)
		}
		_, ipnet, err := net.ParseCIDR(network.String())
		if err != nil {
			return nil, fmt.Errorf("RADIUS client %q has an unusable network %q: %w",
				name, network, err)
		}
		out = append(out, radius.Client{Net: ipnet, Secret: string(secret), Name: name})
	}
	return out, rows.Err()
}

// ssfAddStream registers a Shared Signals receiver.
//
// There was no way to do this at all: the delivery machinery worked and was
// verified, and a stream could only be created by hand-written SQL. A feature
// nobody can configure is one nobody uses.
func ssfAddStream(ctx context.Context, conn *pgx.Conn, orgID, clientID, endpoint,
	token, events string) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this receiver belongs to")
	case clientID == "":
		return fmt.Errorf("give -client, the relying party this stream is for")
	case endpoint == "":
		return fmt.Errorf("give -endpoint, the https URL to push Security Event Tokens to")
	}
	if !strings.HasPrefix(endpoint, "https://") {
		return fmt.Errorf("the endpoint must be https: %q would carry security events "+
			"about real users across the network in the clear", endpoint)
	}

	// The events a receiver actually asked for. An allow-list, because sending
	// one it did not request is at best noise and at worst a disclosure.
	list := []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"}
	if events != "" {
		list = nil
		for _, e := range strings.Split(events, ",") {
			if e = strings.TrimSpace(e); e != "" {
				list = append(list, e)
			}
		}
	}
	for _, e := range list {
		if !slices.Contains(ssf.SupportedEvents(), e) {
			return fmt.Errorf("event %q is not one this engine emits. Supported: %s",
				e, strings.Join(ssf.SupportedEvents(), ", "))
		}
	}

	// The bearer token the receiver issued US. Sealed with the root key: it is a
	// third party's credential and a database backup must not hand it over.
	var sealed []byte
	if token != "" {
		root, err := rootKey()
		if err != nil {
			return err
		}
		sealed, err = root.Seal([]byte(token), "ssf-stream-token")
		if err != nil {
			return fmt.Errorf("sealing the receiver's token: %w", err)
		}
	}

	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, endpoint_url, auth_token,
		                              events_requested)
		VALUES ($1::uuid, $2, $3, $4, $5)
		RETURNING id::text`, orgID, clientID, endpoint, sealed, list).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("client %q already has a stream; one receiver per relying "+
				"party", clientID)
		}
		return err
	}

	fmt.Printf("registered a stream for %s\n  endpoint : %s\n  events   : %s\n",
		clientID, endpoint, strings.Join(list, ", "))
	if token == "" {
		fmt.Println("\n  No -token given. Events are still signed, so the receiver can verify\n" +
			"  them -- but if it requires a bearer token, every push will be refused.")
	} else {
		fmt.Println("\n  The token is sealed with the root key and sent as `Authorization:\n" +
			"  Bearer` on each push.")
	}
	return nil
}

func ssfListStreams(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT s.client_id, s.endpoint_url, s.status, (s.auth_token IS NOT NULL),
		       cardinality(s.events_requested)
		FROM core.ssf_streams s ORDER BY s.client_id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	n := 0
	fmt.Printf("\n  %-24s %-44s %-10s %s\n", "CLIENT", "ENDPOINT", "STATUS", "AUTH")
	for rows.Next() {
		var client, endpoint, status string
		var hasToken bool
		var events int
		if err := rows.Scan(&client, &endpoint, &status, &hasToken, &events); err != nil {
			return err
		}
		n++
		auth := "none"
		if hasToken {
			auth = "bearer"
		}
		fmt.Printf("  %-24s %-44s %-10s %s (%d event types)\n",
			truncate(client, 24), truncate(endpoint, 44), status, auth, events)
	}
	if n == 0 {
		fmt.Println("\n  No Shared Signals receivers. Register one with `signari ssf add-stream`.")
	}
	return rows.Err()
}

// importAuthentik migrates users and groups from an authentik deployment.
func importAuthentik(ctx context.Context, conn *pgx.Conn, path, orgID string, dryRun bool) error {
	if path == "" || orgID == "" {
		return fmt.Errorf("-file and -org are both required.\n\n" +
			"Export from authentik with:\n" +
			"  ak dumpdata authentik_core.User authentik_core.Group > authentik.json")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	exp, err := importer.ParseAuthentik(f)
	if err != nil {
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	res, err := importer.ImportAuthentik(ctx, tx, orgID, exp, dryRun)
	if err != nil {
		return err
	}

	// The hash census FIRST. "We imported 400 users" means nothing if 380 carry
	// a format nothing here can check -- and that is the number which decides
	// whether this migration needs a password reset or not.
	fmt.Printf("\n  password formats found\n")
	for format, n := range res.HashFormats {
		fmt.Printf("    %-46s %d\n", format, n)
	}

	fmt.Printf("\n  users created : %d\n  users updated : %d\n  groups        : %d\n",
		res.UsersCreated, res.UsersUpdated, res.GroupsCreated)

	if len(res.UsersSkipped) > 0 {
		fmt.Printf("\n  skipped (%d):\n", len(res.UsersSkipped))
		for i, s := range res.UsersSkipped {
			if i == 20 {
				fmt.Printf("    ... and %d more\n", len(res.UsersSkipped)-20)
				break
			}
			fmt.Printf("    %s\n", s)
		}
	}

	if dryRun {
		fmt.Println("\n  DRY RUN -- nothing was written. Re-run with -apply.")
		return nil
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("\n  Imported. Everyone signs in with the password they already had:\n" +
		"  the Django hash is verified as-is and replaced with Argon2id on first\n" +
		"  successful sign-in. Nobody needs to reset anything.")
	return nil
}

// registrationEnable turns dynamic client registration on for an organisation.
func registrationEnable(ctx context.Context, conn *pgx.Conn, orgID string, open bool,
	maxClients int, scopes string) error {

	if orgID == "" {
		return fmt.Errorf("give -org, the organisation to enable registration for")
	}
	list := []string{"openid", "profile", "email"}
	if scopes != "" {
		list = nil
		for _, s := range strings.Split(scopes, ",") {
			if s = strings.TrimSpace(s); s != "" {
				list = append(list, s)
			}
		}
	}
	if maxClients <= 0 {
		maxClients = 100
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.registration_policies
			(org_id, enabled, open, max_clients, allowed_scopes)
		VALUES ($1::uuid, true, $2, $3, $4)
		ON CONFLICT (org_id) DO UPDATE SET
			enabled = true, open = EXCLUDED.open, max_clients = EXCLUDED.max_clients,
			allowed_scopes = EXCLUDED.allowed_scopes, updated_at = now()`,
		orgID, open, maxClients, list); err != nil {
		return err
	}

	fmt.Printf("dynamic registration enabled\n  scopes  : %s\n  ceiling : %d clients\n",
		strings.Join(list, ", "), maxClients)
	if open {
		fmt.Println("\n  OPEN: anybody who can reach /oauth2/register may create a client.\n" +
			"  They choose the client_name, and that name appears on a consent screen.\n" +
			"  Prefer `signari registration token` and leave this off unless an\n" +
			"  ecosystem genuinely requires it.")
	} else {
		fmt.Println("\n  Callers need an initial access token: `signari registration token`.")
	}
	return nil
}

// registrationToken mints an initial access token.
func registrationToken(ctx context.Context, conn *pgx.Conn, orgID, name string,
	uses int, expiresIn time.Duration) error {

	if orgID == "" || name == "" {
		return fmt.Errorf("give -org and -name")
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return err
	}
	secret := "sgnreg_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))

	var remaining *int
	if uses > 0 {
		remaining = &uses
	}
	var expires *time.Time
	if expiresIn > 0 {
		t := time.Now().Add(expiresIn)
		expires = &t
	}

	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.registration_tokens (org_id, name, token_hash, remaining, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5) RETURNING id::text`,
		orgID, name, sum[:], remaining, expires).Scan(&id); err != nil {
		return err
	}

	fmt.Printf("\n  %s\n\n  id   : %s\n  name : %s\n", secret, id, name)
	if remaining != nil {
		fmt.Printf("  uses : %d\n", *remaining)
	} else {
		fmt.Println("  uses : unlimited -- consider -uses to bound it")
	}
	fmt.Println("\n  Shown once. Callers present it as `Authorization: Bearer` at\n" +
		"  /oauth2/register.")
	return nil
}

// exportAudit writes the audit trail as CSV, with its integrity stated.
func exportAudit(ctx context.Context, conn *pgx.Conn, orgID, from, to, out string) error {
	parseDay := func(s, what string) (time.Time, error) {
		if s == "" {
			return time.Time{}, nil
		}
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return time.Time{}, fmt.Errorf("-%s must be YYYY-MM-DD: %w", what, err)
		}
		return t, nil
	}
	fromT, err := parseDay(from, "from")
	if err != nil {
		return err
	}
	toT, err := parseDay(to, "until")
	if err != nil {
		return err
	}
	if !fromT.IsZero() && !toT.IsZero() && !toT.After(fromT) {
		return fmt.Errorf("-until (%s) must be after -from (%s)", to, from)
	}

	w := os.Stdout
	if out != "" {
		f, ferr := os.Create(out)
		if ferr != nil {
			return ferr
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	res, err := audit.ExportCSV(ctx, tx, w, audit.ExportOptions{
		OrgID: orgID, From: fromT, To: toT,
	})
	if err != nil {
		return err
	}

	// To stderr, so redirecting stdout to a file still shows the operator what
	// they just produced -- and so the integrity statement can never be mistaken
	// for a row in the data.
	fmt.Fprintf(os.Stderr, "\n  %d rows\n", res.Rows)
	if res.Rows > 0 {
		fmt.Fprintf(os.Stderr, "  first entry hash : %s\n  last entry hash  : %s\n",
			res.FirstHash, res.LastHash)
	}
	if res.ChainVerified && res.Checkpoint != nil {
		// Verified, but only since a declared restart point -- and that has to be
		// stated at least as loudly as the verification itself. An operator who
		// reads "verified" and misses "since" would be citing a document that
		// disclaims the period they care about.
		cp := res.Checkpoint
		fmt.Fprintf(os.Stderr, "\n  Chain verified over %d entries SINCE A CHECKPOINT.\n",
			res.Checked)
		fmt.Fprintf(os.Stderr, "\n  The %d entries before it are NOT asserted by this export.\n",
			cp.SkippedEntries)
		fmt.Fprintf(os.Stderr, "  A checkpoint was declared on %s by %s:\n    %s\n",
			cp.At.Format("2006-01-02"), cp.DeclaredBy, cp.Reason)
		fmt.Fprintln(os.Stderr, "\n  A checkpoint repairs nothing. It records that the earlier chain was\n"+
			"  already broken and that verification restarts here. If you are\n"+
			"  submitting this somewhere that matters, submit the reason with it.")
	} else if res.ChainVerified {
		fmt.Fprintf(os.Stderr, "\n  Chain verified over all %d entries.\n", res.Checked)
		fmt.Fprintln(os.Stderr, "  Every row commits to its predecessor, so this file can be checked\n"+
			"  against the database later: a deleted or altered row breaks the chain\n"+
			"  at its successor, which is why the hashes are a column rather than a\n"+
			"  footnote.")
	} else {
		// Said loudly. An export that carried the appearance of integrity without
		// the fact would be worse than no export at all.
		fmt.Fprintf(os.Stderr, "\n  WARNING: the audit chain is BROKEN at entry %d "+
			"(after checking %d).\n", res.BrokenAt, res.Checked)
		if res.Checkpoint != nil {
			// Said explicitly, because the operator declared that checkpoint and
			// may otherwise assume this is the same old break they already
			// disclaimed. It is not: this one is after it.
			fmt.Fprintf(os.Stderr, "  This break is AFTER the checkpoint declared on %s, "+
				"so it is\n  NOT covered by that declaration. Something has changed "+
				"since.\n", res.Checkpoint.At.Format("2006-01-02"))
		}
		fmt.Fprintln(os.Stderr, "  This file is still the data as stored, but its integrity cannot be\n"+
			"  asserted. Investigate before submitting it anywhere that matters.")
		return fmt.Errorf("the audit chain did not verify")
	}
	return nil
}

// clientCAPool loads the authorities that may issue client certificates.
//
// Separate from the server's own chain on purpose. Trusting the system roots
// here would mean any certificate from any public CA could satisfy
// tls_client_auth, which is thousands of issuers rather than the one an operator
// meant.
//
// nil means no pool, which is correct rather than permissive: with no pool the
// TLS layer produces no VerifiedChains, and tls_client_auth is refused. Only
// self_signed_tls_client_auth works, which is exactly right for a deployment
// that has not configured a CA.
func clientCAPool() *x509.CertPool {
	path := os.Getenv("SIGNARI_TLS_CLIENT_CA")
	if path == "" {
		return nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		// Not fatal: the server still serves, and mutual-TLS clients fail with a
		// specific error rather than the whole deployment refusing to start over
		// an optional file.
		fmt.Fprintf(os.Stderr, "signari: reading SIGNARI_TLS_CLIENT_CA: %v\n", err)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fmt.Fprintf(os.Stderr, "signari: SIGNARI_TLS_CLIENT_CA contained no certificates\n")
		return nil
	}
	return pool
}

// clientSetTLS registers a client for mutual-TLS authentication.
func clientSetTLS(ctx context.Context, conn *pgx.Conn, clientID, subjectDN, sanDNS,
	sanURI, certPath string, boundTokens bool) error {

	if clientID == "" {
		return fmt.Errorf("give -client-id")
	}
	set := 0
	for _, v := range []string{subjectDN, sanDNS, sanURI, certPath} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return fmt.Errorf("give exactly one of -tls-subject-dn, -tls-san-dns, " +
			"-tls-san-uri (PKI) or -sp-cert (self-signed)")
	}
	if set > 1 {
		return fmt.Errorf("give exactly ONE matching rule. Several would be an AND " +
			"nobody expects, and any-of is weaker than it looks")
	}

	var thumb []byte
	if certPath != "" {
		b, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return fmt.Errorf("%s is not PEM", certPath)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%s did not parse as a certificate: %w", certPath, err)
		}
		sum := sha256.Sum256(cert.Raw)
		thumb = sum[:]
	}

	tag, err := conn.Exec(ctx, `
		UPDATE core.clients
		SET tls_subject_dn = NULLIF($2,''), tls_san_dns = NULLIF($3,''),
		    tls_san_uri = NULLIF($4,''), tls_thumbprint = $5,
		    tls_bound_tokens = $6, updated_at = now()
		WHERE client_id = $1`,
		clientID, subjectDN, sanDNS, sanURI, thumb, boundTokens)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}

	method := "tls_client_auth"
	if thumb != nil {
		method = "self_signed_tls_client_auth"
	}
	fmt.Printf("%s now authenticates with %s\n", clientID, method)
	if method == "tls_client_auth" {
		fmt.Println("\n  This needs SIGNARI_TLS_CLIENT_CA set to the authority that issues\n" +
			"  those certificates. Without it the TLS layer verifies no chain and\n" +
			"  the client is refused -- deliberately, since an unverified subject\n" +
			"  string is not an identity.")
	}
	if boundTokens {
		fmt.Println("\n  Access tokens are bound to the certificate (cnf.x5t#S256). A stolen\n" +
			"  token is useless without the private key -- and every caller must now\n" +
			"  present that certificate at the resource server too.")
	}
	return nil
}

// dirAdd registers a directory source.
func dirAdd(ctx context.Context, conn *pgx.Conn, orgID, kind, slug, name, credPath,
	domain, impersonate, tenant, filter, ldapURL, ldapBindDN, ldapPassword,
	ldapBaseDN, ldapFlavour, ldapCAPath string, ldapStartTLS bool) error {

	switch {
	case orgID == "" || slug == "":
		return fmt.Errorf("give -org and -slug")
	case kind != "google" && kind != "entra" && kind != "ldap":
		return fmt.Errorf("-kind must be google, entra or ldap for a directory source "+
			"(got %q; that flag is shared with `idp add`, which uses different values)", kind)
	case credPath == "" && kind != "ldap":
		return fmt.Errorf("give -file: the service account key (google) or credential " +
			"JSON (entra)")
	}

	var raw []byte
	if credPath != "" {
		var rerr error
		raw, rerr = os.ReadFile(credPath)
		if rerr != nil {
			return rerr
		}
	}
	// Parsed now rather than at first sync, so a wrong file is a message here
	// instead of a cron job failing quietly at 3am.
	var ldapCA string
	switch kind {
	case "google":
		if _, perr := directory.ParseGoogleCredentials(raw); perr != nil {
			return perr
		}
		if impersonate == "" {
			return fmt.Errorf("give -impersonate: a Google service account reads " +
				"nothing without domain-wide delegation and an administrator to act as")
		}
	case "entra":
		c, perr := directory.ParseEntraCredentials(raw)
		if perr != nil {
			return perr
		}
		tenant = c.TenantID
	case "ldap":
		if ldapURL == "" || ldapBaseDN == "" {
			return fmt.Errorf("give -ldap-url and -ldap-base-dn")
		}
		if ldapFlavour != "openldap" && ldapFlavour != "ad" && ldapFlavour != "freeipa" {
			return fmt.Errorf("-ldap-flavour must be openldap, ad or freeipa: it decides "+
				"which attribute is the immutable identifier, and reading the wrong one "+
				"makes every rename look like a departure and an arrival (got %q)",
				ldapFlavour)
		}
		if strings.HasPrefix(ldapURL, "ldap://") && !ldapStartTLS {
			return fmt.Errorf("refusing a plaintext bind to %q: the bind password can "+
				"usually read the whole directory. Use ldaps:// or leave StartTLS on",
				ldapURL)
		}
		if ldapCAPath != "" {
			pem, rerr := os.ReadFile(ldapCAPath)
			if rerr != nil {
				return rerr
			}
			// Parsed now rather than at the first sync, so a typo in the path or a
			// file that is not a certificate is a configuration error rather than a
			// sync that fails at 3am.
			if p := x509.NewCertPool(); !p.AppendCertsFromPEM(pem) {
				return fmt.Errorf("%s contains no certificates", ldapCAPath)
			}
			ldapCA = string(pem)
		}
		// The bind password is the credential, sealed like any other.
		raw = []byte(ldapPassword)
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	sealed, err := root.Seal(raw, "directory-credentials")
	if err != nil {
		return err
	}
	if name == "" {
		name = slug
	}

	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.directory_sources
			(org_id, kind, slug, display_name, credentials_enc, domain, impersonate,
			 tenant_id, user_filter, ldap_url, ldap_bind_dn, ldap_base_dn,
			 ldap_flavour, ldap_start_tls, ldap_ca_pem)
		VALUES ($1::uuid, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), $9,
		        NULLIF($10,''), NULLIF($11,''), NULLIF($12,''), NULLIF($13,''), $14,
		        NULLIF($15,''))
		RETURNING id::text`,
		orgID, kind, slug, name, sealed, domain, impersonate, tenant, filter,
		ldapURL, ldapBindDN, ldapBaseDN, ldapFlavour, ldapStartTLS,
		ldapCA).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a source with slug %q already exists in that organisation", slug)
		}
		return err
	}

	fmt.Printf("registered %s (%s)\n  id: %s\n", name, kind, id)
	fmt.Println("\n  It starts in DRY RUN and reports missing users rather than deactivating\n" +
		"  them. Run `signari dir sync -slug " + slug + "` to see what it would do.")
	return nil
}

// dirSync runs one reconciliation.
func dirSync(ctx context.Context, conn *pgx.Conn, slug string, apply bool) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}

	var id, orgID, kind, credsEnc, domain, impersonate, tenant, filter, onMissing string
	var lURL, lBindDN, lBaseDN, lFlavour, lCA string
	var lStartTLS bool
	var sealed []byte
	var dryRun bool
	var maxPct int
	err := conn.QueryRow(ctx, `
		SELECT id::text, org_id::text, kind, credentials_enc, COALESCE(domain,''),
		       COALESCE(impersonate,''), COALESCE(tenant_id,''), user_filter,
		       on_missing, dry_run, max_deactivate_percent,
		       COALESCE(ldap_url,''), COALESCE(ldap_bind_dn,''),
		       COALESCE(ldap_base_dn,''), COALESCE(ldap_flavour,''), ldap_start_tls,
		       COALESCE(ldap_ca_pem,'')
		FROM core.directory_sources WHERE slug = $1 AND enabled`, slug).
		Scan(&id, &orgID, &kind, &sealed, &domain, &impersonate, &tenant, &filter,
			&onMissing, &dryRun, &maxPct,
			&lURL, &lBindDN, &lBaseDN, &lFlavour, &lStartTLS, &lCA)
	if err != nil {
		return fmt.Errorf("no enabled directory source with slug %q: %w", slug, err)
	}
	_ = credsEnc

	root, err := rootKey()
	if err != nil {
		return err
	}
	raw, err := root.Open(sealed, "directory-credentials")
	if err != nil {
		return fmt.Errorf("unsealing the credentials: %w", err)
	}

	pool, err := pgxpool.New(ctx, conn.Config().ConnString())
	if err != nil {
		return err
	}
	defer pool.Close()

	var remote []directory.RemoteUser
	switch kind {
	case "google":
		creds, perr := directory.ParseGoogleCredentials(raw)
		if perr != nil {
			return perr
		}
		remote, err = (&directory.GoogleSource{
			Creds: creds, Impersonate: impersonate, Domain: domain, Query: filter,
		}).Fetch(ctx)
	case "entra":
		creds, perr := directory.ParseEntraCredentials(raw)
		if perr != nil {
			return perr
		}
		remote, err = (&directory.EntraSource{Creds: creds, Filter: filter}).Fetch(ctx)
	case "ldap":
		var pool *x509.CertPool
		if lCA != "" {
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(lCA)) {
				return fmt.Errorf("the stored CA bundle for %q contains no certificates", slug)
			}
		}
		remote, err = (&directory.LDAPSource{
			CAs: pool,
			URL: lURL, BindDN: lBindDN, Password: string(raw), BaseDN: lBaseDN,
			Filter: filter, Flavour: directory.LDAPFlavour(lFlavour),
			StartTLS: lStartTLS,
		}).Fetch(ctx)
	}
	if err != nil {
		directory.RecordFailure(ctx, pool, id, err)
		return err
	}

	local, err := directory.LoadLocal(ctx, pool, id, orgID)
	if err != nil {
		return err
	}

	plan := directory.BuildPlan(remote, local, onMissing, maxPct)
	fmt.Printf("\n  %d users upstream, %d active here\n\n", len(remote), plan.ActiveBefore)
	fmt.Print(plan.Describe())

	if !plan.Safe() {
		// Non-zero: this is the case a cron job must notice.
		return fmt.Errorf("sync refused")
	}
	if dryRun || !apply {
		fmt.Println("\n  DRY RUN -- nothing was written. Re-run with -apply.")
		if dryRun {
			fmt.Println("  (this source is also configured dry_run=true in the database)")
		}
		return nil
	}
	if err := directory.Apply(ctx, pool, id, orgID, plan); err != nil {
		directory.RecordFailure(ctx, pool, id, err)
		return err
	}
	fmt.Println("\n  Applied.")
	return nil
}

// postureFromEnv reads how device trust is established.
//
// Returns nil when nothing is configured, which is the common case and means a
// policy asking about a device will simply never be satisfied -- visible, rather
// than silently permissive.
func postureFromEnv() (*posture.Config, error) {
	cfg := &posture.Config{
		ManagedHeader:   envOr("SIGNARI_DEVICE_MANAGED_HEADER", "X-Device-Managed"),
		CompliantHeader: envOr("SIGNARI_DEVICE_COMPLIANT_HEADER", "X-Device-Compliant"),
	}

	if path := os.Getenv("SIGNARI_DEVICE_CA"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading SIGNARI_DEVICE_CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("SIGNARI_DEVICE_CA contained no certificates")
		}
		cfg.DeviceCAs = pool
	}

	if spec := os.Getenv("SIGNARI_DEVICE_TRUSTED_PROXIES"); spec != "" {
		nets, err := posture.ParseNetworks(spec)
		if err != nil {
			return nil, fmt.Errorf("SIGNARI_DEVICE_TRUSTED_PROXIES: %w", err)
		}
		cfg.TrustedProxies = nets
	}

	if cfg.DeviceCAs == nil && len(cfg.TrustedProxies) == 0 {
		return nil, nil
	}
	return cfg, nil
}

// idpAddSAML registers an upstream SAML identity provider.
//
// Two rows in one transaction: the identity_providers row that every provider
// has, and the saml_sources row carrying what SAML alone needs. One without the
// other is a provider that cannot be used or a configuration nothing reads, so
// neither is written on its own.
func idpAddSAML(ctx context.Context, conn *pgx.Conn, orgID, slug, name, entityID,
	ssoURL, certPath, nameIDFormat string, allowSignup, allowLinking, trustEmail,
	unsolicited, forceAuthn bool, skew int) error {

	switch {
	case entityID == "":
		return fmt.Errorf("give -entity-id: the upstream's entity ID, which is matched " +
			"exactly against the Issuer in every assertion")
	case ssoURL == "":
		return fmt.Errorf("give -sso-url: where AuthnRequests are sent")
	case certPath == "":
		return fmt.Errorf("give -sp-cert: the certificate assertions are verified " +
			"against. Without it there is nothing to check a signature with, and an " +
			"unverified assertion is an attacker's choice of user")
	}

	// transient is deliberately absent: a NameID that differs on every sign-in
	// would create a new orphaned account each time somebody signed in.
	switch nameIDFormat {
	case "", "persistent", "emailAddress", "unspecified":
	default:
		return fmt.Errorf("-nameid-format must be persistent, emailAddress or "+
			"unspecified (got %q). transient is refused: it is a different value on "+
			"every sign-in, so an account linked to it would be abandoned the moment "+
			"it was created", nameIDFormat)
	}
	if nameIDFormat == "" {
		nameIDFormat = "persistent"
	}

	// A SAML assertion carries no email_verified claim: there is no field for
	// one. So the question "is this address verified" has to be answered by the
	// deployment, and the honest answer for an enterprise upstream is yes -- the
	// organisation's own directory authenticated the person and stated their
	// address, which is the entire premise of federating to it.
	//
	// Left false (the OAuth default), a freshly registered SAML source refuses
	// every sign-in with a message about a claim the protocol cannot make. That
	// is a dead feature, and the first deployment to hit it would reasonably
	// conclude the software is broken.
	//
	// The reason this is safe to default on: an address is NEVER used to find or
	// match an account here. It is recorded, displayed, and used for
	// notifications. The takeover vector that makes email trust dangerous
	// elsewhere is closed by internal/federation refusing to match on email at
	// all, under any setting.
	if !trustEmail {
		trustEmail = true
		fmt.Print("note: this source's email addresses are recorded as verified, " +
			"because\n  a SAML assertion has no field to say otherwise. Addresses are " +
			"never used\n  to match accounts, so this affects what is recorded, not who " +
			"can sign in.\n\n")
	}

	// The SSO URL becomes a Location header sent to every user starting a
	// sign-in, so its scheme is checked here rather than trusted later.
	u, err := url.Parse(ssoURL)
	switch {
	case err != nil:
		return fmt.Errorf("-sso-url %q is not a URL: %w", ssoURL, err)
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("-sso-url must be http or https, not %q: this value is "+
			"sent to a browser as a redirect", u.Scheme)
	case u.Host == "":
		return fmt.Errorf("-sso-url %q has no host", ssoURL)
	case u.Scheme == "http" && !strings.HasPrefix(u.Host, "localhost") &&
		!strings.HasPrefix(u.Host, "127.0.0.1"):
		return fmt.Errorf("-sso-url is plaintext http. The AuthnRequest names this " +
			"engine and the user being signed in, and the response comes back over " +
			"the same browser session; use https")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	// Parsed now, so a PEM that is not a certificate is a message here rather
	// than a refused sign-in later.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("%s is not PEM", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%s is not a certificate: %w", certPath, err)
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("that certificate expired on %s, so every assertion it "+
			"signs would be refused", cert.NotAfter.Format("2006-01-02"))
	}
	if name == "" {
		name = slug
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var providerID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.identity_providers
			(org_id, slug, display_name, kind, client_id, scopes,
			 allow_signup, allow_linking, trust_email_verification)
		VALUES ($1::uuid, $2, $3, 'saml', '', '{}', $4, $5, $6)
		RETURNING id::text`,
		orgID, slug, name, allowSignup, allowLinking, trustEmail).Scan(&providerID); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a provider with slug %q is already registered in that "+
				"organisation", slug)
		}
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.saml_sources
			(provider_id, org_id, entity_id, sso_url, cert_pem, name_id_format,
			 force_authn, allow_unsolicited, skew_seconds)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)`,
		providerID, orgID, entityID, ssoURL, string(certPEM), nameIDFormat,
		forceAuthn, unsolicited, skew); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("registered %s (saml source)\n", name)
	fmt.Printf("  sign-in URL  : /saml/source/%s/start\n", slug)
	fmt.Printf("  ACS URL      : <issuer>/saml/source/%s/acs\n", slug)
	fmt.Printf("  metadata     : <issuer>/saml/source/%s/metadata\n", slug)
	fmt.Print("\n  Give the upstream that metadata URL rather than typing the two\n")
	fmt.Print("  values by hand: a mistyped audience produces an assertion this\n")
	fmt.Print("  engine refuses correctly and unhelpfully.\n")
	if unsolicited {
		fmt.Print("\n  WARNING: unsolicited sign-in is enabled. An assertion arriving\n")
		fmt.Print("  without a matching request cannot be tied to a browser, so a valid\n")
		fmt.Print("  one captured anywhere can be posted here to sign somebody in.\n")
	}
	return nil
}

// scimSourceAdd registers an upstream that may provision users into this engine.
func scimSourceAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name,
	onDelete string) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation this upstream provisions into")
	case slug == "":
		return fmt.Errorf("give -slug, a short name for this upstream")
	}
	if name == "" {
		name = slug
	}
	// The flag is shared with `scim add`, where it means the same thing in the
	// other direction.
	switch onDelete {
	case "", "deactivate":
		onDelete = "deactivate"
	case "delete":
	default:
		return fmt.Errorf("-on-deactivate must be deactivate or delete (got %q)", onDelete)
	}

	// 32 bytes. This token can create and deactivate every user in the
	// organisation, so it is generated here rather than chosen, shown once, and
	// stored only as a hash.
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.scim_sources (org_id, slug, display_name, token_hash, on_delete)
		VALUES ($1::uuid, $2, $3, $4, $5)
		RETURNING id::text`,
		orgID, slug, name, sum[:], onDelete).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a SCIM source with slug %q already exists in that "+
				"organisation", slug)
		}
		return err
	}

	fmt.Printf("registered %s\n", name)
	fmt.Printf("  SCIM base URL : <issuer>/scim/v2\n")
	fmt.Printf("  bearer token  : %s\n\n", token)
	fmt.Print("  That token is shown ONCE and stored only as a hash. It can create\n")
	fmt.Print("  and deactivate every user in this organisation; treat it as a\n")
	fmt.Print("  password. Lost tokens are replaced, not recovered.\n")
	if onDelete == "delete" {
		fmt.Print("\n  WARNING: this source is set to DELETE on deprovisioning, which\n")
		fmt.Print("  destroys the audit history of everybody it removes. The default,\n")
		fmt.Print("  deactivate, keeps that history and looks identical upstream.\n")
	}
	return nil
}

// scimSourceList shows the configured upstreams and when each last called.
func scimSourceList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT s.slug, s.display_name, s.on_delete, s.enabled,
		       COALESCE(to_char(s.last_seen_at, 'YYYY-MM-DD HH24:MI'), 'never'),
		       (SELECT count(*) FROM core.scim_source_links l WHERE l.source_id = s.id)
		FROM core.scim_sources s ORDER BY s.slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-16s %-22s %-11s %-8s %-17s %s\n",
		"SLUG", "NAME", "ON DELETE", "ENABLED", "LAST SEEN", "USERS")
	for rows.Next() {
		var slug, name, onDelete, lastSeen string
		var enabled bool
		var users int
		if err := rows.Scan(&slug, &name, &onDelete, &enabled, &lastSeen, &users); err != nil {
			return err
		}
		fmt.Printf("%-16s %-22s %-11s %-8t %-17s %d\n",
			slug, name, onDelete, enabled, lastSeen, users)
	}
	return rows.Err()
}

// duoSet stores an organisation's Duo integration.
//
// The keys are checked against Duo itself before they are stored. A
// configuration that cannot authenticate is worth finding out about now rather
// than at somebody's next sign-in, and Duo's health check reports exactly which
// of the three values is wrong.
func duoSet(ctx context.Context, conn *pgx.Conn, orgID, clientID, secret, apiHost string,
	failOpen bool) error {

	if orgID == "" {
		return fmt.Errorf("give -org, the organisation this Duo integration belongs to")
	}
	cfg := &duo.Config{
		ClientID: clientID, ClientSecret: secret, APIHost: apiHost,
		// Not used by the health check, and required by Validate, so a
		// placeholder that is obviously a placeholder.
		RedirectURI: "https://configured-at-runtime.invalid/login/duo/callback",
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	// The same development-only override the engine honours, gated on the same
	// flag. Without it here, `duo set` would check the keys against real Duo
	// while the engine used the stand-in -- two different answers to the same
	// question.
	if base := os.Getenv("SIGNARI_DUO_BASE_URL"); base != "" {
		if err := cfg.SetInsecureBaseURL(base,
			os.Getenv("SIGNARI_INSECURE_ISSUER") == "1"); err != nil {
			return err
		}
		fmt.Printf("using the Duo stand-in at %s (development only)\n", base)
	}

	fmt.Print("checking these keys against Duo... ")
	if err := cfg.HealthCheck(ctx); err != nil {
		fmt.Println("failed")
		return fmt.Errorf("%w\n\n  Nothing has been stored. The three values come from "+
			"one Duo application:\n"+
			"    -duo-client-id   the integration key\n"+
			"    -duo-secret      the secret key\n"+
			"    -duo-api-host    the API hostname", err)
	}
	fmt.Println("ok")

	root, err := rootKey()
	if err != nil {
		return err
	}
	sealed, err := root.Seal([]byte(secret), "duo_secret")
	if err != nil {
		return fmt.Errorf("sealing the Duo secret: %w", err)
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.duo_integrations (org_id, client_id, secret_enc, api_host, fail_open)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (org_id) DO UPDATE SET
			client_id = EXCLUDED.client_id, secret_enc = EXCLUDED.secret_enc,
			api_host = EXCLUDED.api_host, fail_open = EXCLUDED.fail_open,
			enabled = true, updated_at = now()`,
		orgID, clientID, sealed, apiHost, failOpen); err != nil {
		return err
	}

	fmt.Printf("\nDuo configured for %s\n", apiHost)
	fmt.Print("  redirect URI : <issuer>/login/duo/callback\n")
	fmt.Print("     register that in the Duo admin panel, exactly as written\n")
	fmt.Print("\n  Enrol users with `signari duo enroll -email <address> -duo-username <name>`.\n")
	fmt.Print("  Duo identifies people by ITS username, which is often not their email.\n")
	if failOpen {
		fmt.Print("\n  WARNING: fail-open is on. When Duo is unreachable, users sign in\n")
		fmt.Print("  WITHOUT a second factor. An attacker who can stop one person's\n")
		fmt.Print("  traffic reaching Duo has removed their second factor; blocking one\n")
		fmt.Print("  host is not a high bar. Each occurrence is audited as\n")
		fmt.Print("  mfa.duo_unavailable with fail_open=true.\n")
	}
	return nil
}

// duoEnroll maps a local user to their Duo username.
func duoEnroll(ctx context.Context, conn *pgx.Conn, orgID, email, duoUsername string) error {
	switch {
	case email == "":
		return fmt.Errorf("give -email, the local account to enrol")
	case duoUsername == "":
		return fmt.Errorf("give -duo-username: the name this person has IN DUO, which " +
			"is what Duo returns and what the sign-in is checked against. It is " +
			"frequently not their email address")
	}

	var userID, foundOrg string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, org_id::text FROM core.users WHERE lower(email) = lower($1)`,
		email).Scan(&userID, &foundOrg); err != nil {
		return fmt.Errorf("no user with address %q", email)
	}
	if orgID != "" && orgID != foundOrg {
		return fmt.Errorf("%s belongs to a different organisation", email)
	}

	var configured bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM core.duo_integrations WHERE org_id = $1::uuid AND enabled)`,
		foundOrg).Scan(&configured); err != nil {
		return err
	}
	if !configured {
		return fmt.Errorf("that organisation has no Duo integration; run `signari duo set` " +
			"first, or the enrolment would be a factor nobody can present")
	}

	if err := store.EnrollDuo(ctx, conn, userID, foundOrg, duoUsername); err != nil {
		return err
	}
	fmt.Printf("enrolled %s as %q in Duo\n", email, duoUsername)
	fmt.Print("  Their next sign-in will require a Duo prompt after their password.\n")
	return nil
}

// duoShow lists the configured integrations.
func duoShow(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT i.org_id::text, i.client_id, i.api_host, i.fail_open, i.enabled,
		       (SELECT count(*) FROM core.duo_enrollments e WHERE e.org_id = i.org_id)
		FROM core.duo_integrations i ORDER BY i.created_at`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-38s %-22s %-36s %-10s %-8s %s\n",
		"ORG", "CLIENT ID", "API HOST", "FAIL OPEN", "ENABLED", "ENROLLED")
	for rows.Next() {
		var org, clientID, host string
		var failOpen, enabled bool
		var enrolled int
		if err := rows.Scan(&org, &clientID, &host, &failOpen, &enabled, &enrolled); err != nil {
			return err
		}
		fmt.Printf("%-38s %-22s %-36s %-10t %-8t %d\n",
			org, clientID, host, failOpen, enabled, enrolled)
	}
	return rows.Err()
}

// eapTLSFromEnv builds the EAP-TLS configuration, or nil when it is not wanted.
//
// All three settings or none. A partial configuration is refused rather than
// half-applied: a listener with a server certificate and no client CAs would
// complete handshakes with anybody holding any certificate, which is worse than
// no EAP-TLS at all because it looks like it is working.
func eapTLSFromEnv(pool *pgxpool.Pool, orgID string) (*radius.EAPTLSConfig, error) {
	certFile := os.Getenv("SIGNARI_EAP_TLS_CERT")
	keyFile := os.Getenv("SIGNARI_EAP_TLS_KEY")
	caFile := os.Getenv("SIGNARI_EAP_CLIENT_CA")

	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}
	switch {
	case certFile == "" || keyFile == "":
		return nil, fmt.Errorf("EAP-TLS needs SIGNARI_EAP_TLS_CERT and " +
			"SIGNARI_EAP_TLS_KEY: supplicants verify this certificate, and one they " +
			"do not trust makes every login fail with no message anybody can read")
	case caFile == "":
		return nil, fmt.Errorf("EAP-TLS needs SIGNARI_EAP_CLIENT_CA: without the " +
			"authorities that issue supplicant certificates there is nothing to " +
			"verify one against, and the handshake would admit anybody holding any " +
			"certificate")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the EAP-TLS server certificate: %w", err)
	}
	// Checked now rather than at the first association: an expired certificate
	// makes every supplicant refuse the server, and the error they show says
	// nothing useful.
	if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
		if time.Now().After(leaf.NotAfter) {
			return nil, fmt.Errorf("the EAP-TLS server certificate expired on %s",
				leaf.NotAfter.Format("2006-01-02"))
		}
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool2 := x509.NewCertPool()
	if !pool2.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no certificates", caFile)
	}

	return &radius.EAPTLSConfig{
		Certificate: cert,
		ClientCAs:   pool2,
		Auth: httpapi.NewEAPCertAuthenticator(pool, orgID,
			os.Getenv("SIGNARI_EAP_IDENTITY_FROM")),
	}, nil
}

func policyGraph(path, out string) error {
	if path == "" {
		return fmt.Errorf("give -policy-file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Parsed, not just read: Parse runs the file's own tests, so a diagram is
	// only ever drawn for a file that would actually load. Drawing a broken
	// policy would put a picture of something that cannot deploy in front of
	// somebody reviewing it.
	f, err := policy.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	svg := f.SVG()
	if out == "" {
		fmt.Println(svg)
		return nil
	}
	if err := os.WriteFile(out, []byte(svg), 0o644); err != nil {
		return err
	}
	create, deny := 0, 0
	for _, r := range f.Policies {
		if r.Deny {
			deny++
		} else {
			create++
		}
	}
	fmt.Printf("wrote %s\n", out)
	fmt.Printf("  %d rule(s) -- %d restricting, %d denying\n", len(f.Policies), create, deny)
	fmt.Printf("  %d test(s), all passing (a file whose tests fail does not load)\n",
		len(f.Tests))
	return nil
}

// radiusSetClientEnabled revokes or restores a network device's access.
//
// This did not exist. The column did, so an operator could revoke a device by
// editing the database by hand -- and the running listener would carry on
// answering it anyway, because the client list was read once at startup. Two
// halves of the same gap: no way to say it, and no effect if you did.
func radiusSetClientEnabled(ctx context.Context, conn *pgx.Conn, name string,
	enabled bool) error {

	if name == "" {
		return fmt.Errorf("give -name, the device to change (see `signari radius list`)")
	}
	tag, err := conn.Exec(ctx, `
		UPDATE core.radius_clients SET enabled = $2, updated_at = now()
		WHERE name = $1`, name, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no RADIUS client named %q", name)
	}

	if enabled {
		fmt.Printf("enabled %s\n", name)
	} else {
		fmt.Printf("disabled %s\n", name)
	}
	fmt.Print("  Running listeners pick this up within a minute; there is no need\n")
	fmt.Print("  to restart them.\n")
	if !enabled {
		// Said plainly, because it is the question somebody asks next and the
		// answer is not obvious from the command they just ran.
		fmt.Print("\n  This stops the device authenticating. It does NOT end sessions\n")
		fmt.Print("  already established through it -- RADIUS has no way to reach back\n")
		fmt.Print("  into a switch and close them.\n")
	}
	return nil
}

// auditCheckpoint declares a restart point in a chain that is already broken.
//
// It repairs nothing. See internal/audit/checkpoint.go for why that is the
// point rather than a limitation.
func auditCheckpoint(ctx context.Context, conn *pgx.Conn, orgID, by, reason string) error {
	if orgID == "" {
		var err error
		if orgID, err = firstOrg(ctx, conn); err != nil {
			return err
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cp, err := audit.DeclareCheckpoint(ctx, tx, orgID, by, reason)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("checkpoint declared at audit entry %d\n", cp.EntryID)
	fmt.Printf("  %d earlier entries are no longer asserted by an export\n",
		cp.SkippedEntries)
	fmt.Printf("  declared by : %s\n  reason      : %s\n", cp.DeclaredBy, cp.Reason)
	fmt.Print("\n  Nothing was repaired, moved or removed. Every export that crosses\n")
	fmt.Print("  this point will say so, and will carry that reason with it.\n")
	return nil
}

// racAdd registers a machine somebody may reach through the browser.
func racAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name, protocol,
	host string, port int, login, password, requireGroup, recording string) error {

	switch {
	case orgID == "":
		var err error
		if orgID, err = firstOrg(ctx, conn); err != nil {
			return err
		}
	}
	switch {
	case slug == "":
		return fmt.Errorf("give -slug, the short name used in the URL")
	case host == "":
		return fmt.Errorf("give -host, the machine to connect to")
	case protocol != "rdp" && protocol != "vnc" && protocol != "ssh":
		return fmt.Errorf("-protocol must be rdp, vnc or ssh (got %q)", protocol)
	}
	if port == 0 {
		switch protocol {
		case "rdp":
			port = 3389
		case "vnc":
			port = 5900
		case "ssh":
			port = 22
		}
	}
	if name == "" {
		name = slug
	}

	// The credentials are sealed, never stored in the parameters column: a
	// database read must not be a working login to somebody's estate.
	root, err := rootKey()
	if err != nil {
		return err
	}
	secrets := map[string]string{}
	if login != "" {
		secrets["username"] = login
	}
	if password != "" {
		secrets["password"] = password
	}
	sealed, err := store.SealRACSecrets(root, secrets)
	if err != nil {
		return err
	}

	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.rac_connections
			(org_id, slug, display_name, protocol, hostname, port, secrets_enc,
			 require_group, recording_path)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, NULLIF($8,''), NULLIF($9,''))
		RETURNING id::text`,
		orgID, slug, name, protocol, host, port, sealed, requireGroup, recording).
		Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a connection with slug %q already exists in that "+
				"organisation", slug)
		}
		return err
	}

	fmt.Printf("registered %s (%s to %s:%d)\n", name, protocol, host, port)
	fmt.Printf("  connect URL : <issuer>/rac/connect/%s\n", slug)
	if requireGroup == "" {
		// Said out loud. A machine nobody restricted is a machine everybody has,
		// and the default should not be discovered later.
		fmt.Print("\n  WARNING: no -group was given, so ANY signed-in user in this\n")
		fmt.Print("  organisation may reach this machine, subject only to the access\n")
		fmt.Print("  policy. Add one with -group unless that is what you meant.\n")
	} else {
		fmt.Printf("  restricted to group: %s\n", requireGroup)
	}
	if recording == "" {
		fmt.Print("\n  No -recording-path: sessions are not recorded.\n")
	}
	fmt.Print("\n  Set SIGNARI_GUACD_ADDR for the listener to accept connections.\n")
	return nil
}

// racList shows the registered machines.
func racList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT slug, display_name, protocol, hostname, port,
		       COALESCE(require_group, '(anyone)'),
		       recording_path IS NOT NULL, enabled
		FROM core.rac_connections ORDER BY display_name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-14s %-22s %-6s %-28s %-14s %-9s %s\n",
		"SLUG", "NAME", "PROTO", "TARGET", "GROUP", "RECORDED", "ENABLED")
	for rows.Next() {
		var slug, name, protocol, host, group string
		var port int
		var recorded, enabled bool
		if err := rows.Scan(&slug, &name, &protocol, &host, &port, &group,
			&recorded, &enabled); err != nil {
			return err
		}
		fmt.Printf("%-14s %-22s %-6s %-28s %-14s %-9t %t\n",
			slug, name, protocol, fmt.Sprintf("%s:%d", host, port), group,
			recorded, enabled)
	}
	return rows.Err()
}

// brandCheck reports whether a palette is readable, without touching anything.
//
// Separate from `brand set` so colours can be tried against the standard before
// they are committed. The arithmetic is the same either way; what differs is
// that this one cannot break a running deployment.
func brandCheck(primary, onPrimary, background, text string) error {
	b := &brand.Brand{Primary: primary, OnPrimary: onPrimary,
		Background: background, Text: text}
	if err := b.Validate(); err != nil {
		return err
	}
	if primary == "" {
		return fmt.Errorf("give the four colours: -brand-primary, -brand-on-primary, " +
			"-brand-background and -brand-text")
	}
	for _, p := range []struct{ a, b, what string }{
		{text, background, "text on the background"},
		{onPrimary, primary, "button text on the button"},
	} {
		r, err := brand.Contrast(p.a, p.b)
		if err != nil {
			return err
		}
		fmt.Printf("  %-28s %5.2f:1  %s\n", p.what, r, verdictFor(r))
	}
	fmt.Println("\nreadable (WCAG 2.1 AA needs 4.5:1 for body text)")
	return nil
}

func verdictFor(r float64) string {
	switch {
	case r >= 7:
		return "comfortable (AAA)"
	case r >= 4.5:
		return "readable (AA)"
	default:
		return "TOO LOW"
	}
}

func brandSet(ctx context.Context, conn *pgx.Conn, issuer, name, logo, support,
	primary, onPrimary, background, text string) error {

	if issuer == "" {
		return fmt.Errorf("give -issuer, the issuer URL of the instance to brand")
	}
	b := &brand.Brand{ProductName: name, LogoURL: logo, SupportURL: support,
		Primary: primary, OnPrimary: onPrimary, Background: background, Text: text}
	if err := b.Validate(); err != nil {
		return err
	}

	var instanceID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.instances WHERE issuer = $1`, issuer).Scan(&instanceID); err != nil {
		return fmt.Errorf("no instance is registered with issuer %q", issuer)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.brands (instance_id, product_name, logo_url, support_url,
		                         colour_primary, colour_on_primary,
		                         colour_background, colour_text)
		VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''),
		        NULLIF($5,''), NULLIF($6,''), NULLIF($7,''), NULLIF($8,''))
		ON CONFLICT (instance_id) DO UPDATE SET
			product_name = EXCLUDED.product_name, logo_url = EXCLUDED.logo_url,
			support_url = EXCLUDED.support_url,
			colour_primary = EXCLUDED.colour_primary,
			colour_on_primary = EXCLUDED.colour_on_primary,
			colour_background = EXCLUDED.colour_background,
			colour_text = EXCLUDED.colour_text, updated_at = now()`,
		instanceID, name, logo, support, primary, onPrimary, background, text); err != nil {
		return err
	}
	fmt.Printf("branded %s\n", issuer)
	if primary != "" {
		r, _ := brand.Contrast(text, background)
		fmt.Printf("  text contrast %.1f:1 (%s)\n", r, verdictFor(r))
	}
	fmt.Println("  takes effect on the next page render; no restart needed")
	return nil
}

func brandShow(ctx context.Context, conn *pgx.Conn, issuer string) error {
	if issuer == "" {
		return fmt.Errorf("give -issuer, the issuer URL of the instance")
	}
	var name, logo, support, p, op, bg, tx *string
	err := conn.QueryRow(ctx, `
		SELECT product_name, logo_url, support_url, colour_primary,
		       colour_on_primary, colour_background, colour_text
		FROM core.brands b JOIN core.instances i ON i.id = b.instance_id
		WHERE i.issuer = $1`, issuer).Scan(&name, &logo, &support, &p, &op, &bg, &tx)
	if err != nil {
		fmt.Printf("%s has no brand set; pages use the default appearance\n", issuer)
		return nil
	}
	show := func(label string, v *string) {
		if v != nil && *v != "" {
			fmt.Printf("  %-14s %s\n", label, *v)
		}
	}
	fmt.Printf("%s\n", issuer)
	show("name", name)
	show("logo", logo)
	show("support", support)
	show("primary", p)
	show("on-primary", op)
	show("background", bg)
	show("text", tx)
	return nil
}
