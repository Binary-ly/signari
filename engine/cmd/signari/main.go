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
	"gopkg.in/yaml.v3"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/config"
	"signari.dev/engine/internal/kerberos"
	"signari.dev/engine/internal/logouttest"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/outpost"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/provision"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/adminapi"
	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/auditsink"
	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/doctor"
	"signari.dev/engine/internal/duo"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/fidomds"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/httpapi"
	"signari.dev/engine/internal/importer"
	"signari.dev/engine/internal/janitor"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/metrics"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/oidfed"
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
	"invite": true, "signup": true, "outpost": true, "provision": true,
	"provider": true,
	"erase":    true,
	"prompt":   true,
	"attester": true,
	"flow":     true,
	"kerberos": true,
	"ssf":      true, "registration": true, "export": true, "dir": true, "audit": true, "rac": true,
	"events":     true,
	"authz":      true,
	"federation": true,
	"trust-mark": true,
	"uma":        true,
	"theme":      true,
	"i18n":       true,
	"credential": true,
	"rar":        true,
}

func usage() error {
	fmt.Fprint(os.Stderr, `usage: signari <command> [flags]

commands:
  migrate bootstrap   apply 0001 (roles, schemas, grants) -- needs a superuser DSN
  migrate up          apply 0002+ (tables, policies, views) as signari_engine
  migrate all         bootstrap then up, in one invocation (for containers)
  migrate status      show applied version, pending migrations, live fingerprint
  migrate fingerprint print ONLY the schema fingerprint, for pinning a build
  verify              run the startup schema gate and exit
  instance create     create an instance and its first signing keys
  user create         create a user with a password
  client create       register an OAuth client
  client set-keys     switch a client to private_key_jwt with its public JWKS
  client set-tls      authenticate a client by TLS certificate (RFC 8705)
  client set-assertion-issuers  which issuers' assertions a client may exchange
  janitor once        run one maintenance pass (serve runs this continuously)
  import keycloak     import users and clients from a Keycloak realm export
  import authentik    import users and groups from an authentik dumpdata export
  keys list           show signing keys, their state and when each may advance
  keys rotate         advance the rotation one safe step (run it again later)
  keys retire         remove passive keys nothing can still be verifying against
  proxy check         prove a forward-auth deployment actually protects the app
  saml add-sp         register a SAML service provider
  saml list           show registered SAML service providers
  idp add             register an external sign-in provider (Google, GitHub, ...)
  idp list            show external sign-in providers
  idp assertions      allow or refuse RFC 7523 assertions from a provider
  idp add-issuer      register a key-publishing issuer for the jwt-bearer grant
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
  flow test           check a sign-in flow file (no database needed -- for CI)
  flow paths          list every journey a flow admits, and what produces each
  flow apply          install a sign-in flow file
  flow show           print the built-in flows, as a file to start from
  dir add             register a Google Workspace or Entra ID directory source
  dir sync            reconcile users from a directory (preview unless -apply)
  export audit        write the audit trail as CSV, with its chain verified
  erase subject       destroy a subject key, making their data unreadable forever
  registration enable turn on dynamic client registration (RFC 7591)
  registration token  mint an initial access token for registration
  ssf add-stream      register a Shared Signals receiver for CAEP events
  ssf list            show Shared Signals receivers
  radius add-client   register a network device permitted to send Access-Requests
  radius list         show registered RADIUS clients
  admin-token create  mint a scoped, revocable admin API token
  admin-token list    show admin tokens, their scopes and when each was last used
  admin-token revoke  revoke one immediately, with no restart
  theme eject         write the built-in HTML pages out so they can be edited
  theme check         validate a theme directory; non-zero if anything is refused
  theme list          which page is built-in and which is overridden
  uma settings        offer, or stop offering, resource-owner intervention on refused UMA requests
  uma requests        UMA requests waiting for a resource owner to decide
  uma approve         grant a relation and let a submitted UMA request through
  uma deny            close a submitted UMA request without granting anything
  trust-mark issue    issue an OpenID Federation Trust Mark to an entity
  trust-mark revoke   withdraw a Trust Mark this entity issued
  trust-mark list     Trust Marks this entity issues and holds
  trust-mark accept   publish a Trust Mark somebody granted this entity
  trust-mark drop     stop publishing a Trust Mark
  trust-mark delegate authorise another entity to issue a Trust Mark type we own
  trust-mark issuers  set trust_mark_issuers (Trust Anchor only)
  trust-mark owners   set trust_mark_owners (Trust Anchor only)
  federation enable   join an OpenID Federation: generate an Entity Statement key
                      and publish /.well-known/openid-federation
  federation show     print the Entity Configuration this instance publishes
  client set-grants   set which grant types a client may use
  credential offer    mint an OID4VCI Credential Offer a wallet can redeem
  credential define   define a credential this issuer can mint (SD-JWT VC)
  credential list     show the credential configurations this issuer publishes
  rar register        register an RFC 9396 authorization details type
  rar allow           let a client request a registered type
  rar list            show registered types and which clients may use them
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
	// The admin API served plaintext until this existed, which put a bearer token
	// carrying every write privilege on the wire in clear. TLS is now the default
	// and plaintext has to be asked for by name.
	//
	// Fail closed rather than warn: a warning in a log nobody reads is how the
	// previous behaviour survived. The escape hatch is real, because binding to
	// loopback behind a trusted terminator is a legitimate deployment -- it just
	// should not be what somebody gets by forgetting.
	adminInsecure := fs.Bool("admin-insecure", os.Getenv("SIGNARI_ADMIN_INSECURE") == "1",
		"serve the admin API over plaintext HTTP (requires no -tls-cert; only safe on loopback behind a trusted terminator)")
	email := fs.String("email", "", "user email")
	password := fs.String("password", "", "user password")
	clientID := fs.String("client-id", "", "OAuth client_id (settable verbatim, for migration)")
	redirect := fs.String("redirect", "", "registered redirect_uri (exact match)")
	public := fs.Bool("public", false, "register a public client (PKCE, no secret)")
	// Defaults to true, matching the column default, because PKCE is required for
	// every client by RFC 9700 and OAuth 2.1. The flag exists because the OIDC
	// Basic profile -- the one the certification plan of that name exercises --
	// predates that rule and sends no challenge, so a deployment seeking Basic OP
	// certification needs a client that permits it. Without the flag the only way
	// to set the column was an UPDATE by hand.
	requirePKCE := fs.Bool("require-pkce", true,
		"refuse an authorization request from this client that carries no PKCE challenge")
	file := fs.String("file", "", "path to a realm export (import)")
	orgID := fs.String("org", "", "organisation uuid to import into")
	dryRun := fs.Bool("dry-run", false, "report what would be imported or retired and change nothing")
	alg := fs.String("alg", "", "restrict `keys rotate` to one algorithm (default: all in use)")
	promoteNow := fs.Bool("now", false, "promote without waiting for the publication dwell -- key compromise only")
	allowAssertions := fs.Bool("allow-assertions", false, "`idp assertions`: let this provider's JWTs be exchanged for tokens (RFC 7523)")
	jwksURL := fs.String("jwks-url", "", "`idp add-issuer`: URL publishing the issuer's signing keys")
	assertionIssuers := fs.String("issuers", "",
		"`client set-assertion-issuers`: comma-separated provider slugs, or empty to permit none")
	eraseSubject := fs.String("subject-id", "", "`erase subject`: the subject uuid to erase")
	eraseConfirm := fs.String("confirm", "",
		"`erase subject`: repeat the subject uuid to confirm; erasure cannot be undone")
	eraseDeactivate := fs.Bool("deactivate", false,
		"`erase subject`: also deactivate the account, required when it is still active")
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
	ssfCritical := fs.String("critical-subject-members", "",
		"comma-separated subject member names this transmitter marks Critical (SSF 1.0 section 3.6)")
	attesterJWKS := fs.String("attester-jwks", "", "path to a JWKS file holding the client attester's PUBLIC keys")
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
	ssfPoll := fs.Bool("poll", false, "create a poll stream (RFC 8936): the receiver pulls from /ssf/poll instead of us pushing")
	providerURL := fs.String("provider-url", "", "https endpoint of the extension service to call")
	providerHook := fs.String("hook", "", "which decision it extends ("+providerHookList()+")")
	providerMode := fs.String("mode", "", "what happens when it cannot be reached: fail_closed or fail_open. REQUIRED -- there is no default")
	providerTimeout := fs.Duration("provider-timeout", 2*time.Second, "how long to wait for it (max 5s)")
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
	tlsSANIP := fs.String("tls-san-ip", "", "certificate iPAddress SAN that must match (RFC 8705)")
	tlsSANEmail := fs.String("tls-san-email", "", "certificate rfc822Name SAN that must match (RFC 8705)")
	tlsBound := fs.Bool("tls-bound-tokens", false, "issue certificate-bound access tokens (RFC 8705)")
	dpopBound := fs.Bool("dpop-bound", false, "RFC 9449 §5.2: refuse token requests from this client that carry no DPoP proof")
	exchangeAudMatch := fs.Bool("exchange-audience-match", false, "RFC 8693: only exchange subject tokens this client holds or is named in the audience of")
	promptFile := fs.String("prompt-file", "", "YAML defining a sign-in prompt")
	configFile := fs.String("f", "", "declarative configuration file")
	prune := fs.Bool("prune", false,
		"delete anything the file does not mention. Off by default: a missing "+
			"line should not take down an application")
	keytabPath := fs.String("keytab", "", "path to the service keytab")
	krbRealm := fs.String("realm", "", "Kerberos realm, e.g. EXAMPLE.COM")
	krbAdmin := fs.String("admin-principal", "",
		"administrative principal kadmin authenticates as, e.g. signari/admin@EXAMPLE.COM")
	krbSPN := fs.String("spn", "", "service principal, e.g. HTTP/auth.example.com")
	credsFile := fs.String("credentials", "",
		"path to the Google service account JSON or Entra client credentials")
	targetDomain := fs.String("target-domain", "",
		"domain new accounts are created under")
	appleTeam := fs.String("apple-team", "", "Apple team id (ten characters)")
	appleKeyID := fs.String("apple-key-id", "", "id of the .p8 key")
	appleKeyFile := fs.String("apple-key", "", "path to the .p8 private key")
	rpURL := fs.String("rp-url", "", "the relying party's backchannel_logout_uri")
	subject := fs.String("subject", "", "sub to name in the logout token")
	sidFlag := fs.String("sid", "", "sid to name in the logout token")
	reviewBy := fs.String("review-by", "",
		"YYYY-MM-DD when the hybrid exemption should be revisited")
	outpostCore := fs.String("core", "", "URL of the Signari engine this outpost asks")
	outpostToken := fs.String("outpost-token", "", "outpost token from `signari outpost create`")
	outpostKind := fs.String("kind-outpost", "", "ldap, radius or proxy")
	subURL := fs.String("url", "", "https endpoint events are POSTed to")
	srcIssuer := fs.String("source-issuer", "", "the transmitter's issuer")
	srcJWKS := fs.String("source-jwks", "", "the transmitter's JWKS URI (https)")
	srcAudience := fs.String("source-audience", "", "what the transmitter puts in aud for us")
	modelFile := fs.String("model-file", "", "authorization model, YAML")
	authorityHints := fs.String("authority-hints", "",
		"comma-separated Entity Identifiers of this entity's Immediate Superiors "+
			"(federation enable). Leave empty only for a Trust Anchor with no superiors")
	orgName := fs.String("organization-name", "", "organisation name published in the Entity Configuration")
	// Every trust-mark flag carries the prefix. Names like -sub and -type would
	// collide with flags this binary already registers, and Go's flag package
	// panics on a duplicate registration -- which breaks EVERY command, not just
	// the new one. (It has happened here before; TestNoTwoFlagsShareAName exists
	// because of it.)
	tmType := fs.String("trust-mark-type", "",
		"Trust Mark type identifier, a URL that is collision-resistant across federations (section 7.1)")
	tmSubject := fs.String("trust-mark-sub", "",
		"Entity Identifier the Trust Mark is issued to")
	tmLifetime := fs.Duration("trust-mark-lifetime", 0,
		"how long the Trust Mark is valid. Zero issues one with no exp, which section 7.1 permits and which readers can only re-check at the status endpoint")
	tmLogo := fs.String("trust-mark-logo", "", "https URL of a logo for the Trust Mark")
	tmRef := fs.String("trust-mark-ref", "",
		"https URL of human-readable information about the issuance")
	tmFile := fs.String("trust-mark-file", "",
		"file containing a Trust Mark JWT (trust-mark accept), or a JSON claim document (trust-mark issuers/owners)")
	tmIssuer := fs.String("trust-mark-issuer", "",
		"Entity Identifier of the Trust Mark issuer (trust-mark drop)")
	tmDelegate := fs.String("trust-mark-delegate", "",
		"Entity Identifier being authorised to issue on this owner's behalf")
	tmDelegation := fs.String("trust-mark-delegation", "",
		"file containing a Trust Mark Delegation JWT to embed in the issued mark")
	tmReason := fs.String("trust-mark-reason", "", "why the Trust Mark is being revoked")
	themeDir := fs.String("theme-dir", "",
		"directory of .html page overrides. Defaults to SIGNARI_THEME_DIR")
	themeOnly := fs.String("theme-page", "", "eject only this page")
	themeForce := fs.Bool("theme-force", false, "overwrite files that already exist (theme eject)")
	umaIntervention := fs.Bool("owner-intervention", false,
		"record refused UMA requests for a resource owner to decide (UMA 2.0 section 3.3.6 request_submitted). Off means a refusal is final")
	umaPoll := fs.Duration("poll-interval", 30*time.Second,
		"how often a client should poll a submitted UMA request, 5s to 1h")
	umaRequestID := fs.String("uma-request", "", "identifier from `signari uma requests`")
	claimsRedirects := fs.String("claims-redirect-uris", "",
		"comma-separated https URIs a requesting party may be returned to after claims gathering (UMA 2.0 section 3.3.2). Empty registers none, which refuses claims gathering for this client")
	homepageURI := fs.String("homepage-uri", "", "homepage published in the Entity Configuration")
	relSubject := fs.String("principal", "", "type:id, e.g. user:alice@example.com")
	relRelation := fs.String("relation", "", "e.g. editor")
	relObject := fs.String("object", "", "type:id, e.g. document:42")
	relAction := fs.String("action", "", "e.g. write")
	subEvents := fs.String("event-types", "", "comma-separated event types, or empty for all")
	inviteGroups := fs.String("groups", "", "comma-separated groups the new account joins")
	inviteTTL := fs.Duration("expires", 7*24*time.Hour, "how long the invitation lasts")
	signupDomains := fs.String("domains", "",
		"comma-separated email domains permitted to self-sign-up")
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
	kind := fs.String("kind", "oidc", strings.Join(kindNamesForHelp(), ", "))
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
	flowFile := fs.String("flow-file", "", "path to a sign-in flow file")
	flowName := fs.String("flow", "", "which flow in the file (default: every one)")
	jwksPath := fs.String("jwks", "", "file containing the client's PUBLIC JWKS")
	onlyGroups := fs.String("only", "", "comma-separated groups to release (default: all)")
	apply := fs.Bool("apply", false, "actually make changes (scim sync defaults to a preview)")
	grantTypes := fs.String("grant-types", "",
		"comma-separated grant types this client may use, replacing what it has: "+
			strings.Join(knownGrantTypes, ", "))
	credVCT := fs.String("vct", "", "SD-JWT VC type identifier, a collision-resistant name (credential define)")
	credAlways := fs.String("always", "",
		"comma-separated claims every verifier sees, whatever the holder chooses")
	credSelective := fs.String("selective", "",
		"comma-separated claims the holder reveals one at a time")
	credLifetime := fs.Duration("valid-for", 0,
		"how long an issued credential is valid (0 = no exp claim)")
	rarType := fs.String("type", "", "authorization details type identifier (rar)")
	rarFields := fs.String("fields", "",
		"comma-separated common data fields this type uses: "+
			"locations, actions, datatypes, identifier, privileges")
	rarRequired := fs.String("required", "",
		"comma-separated subset of -fields that must be present")
	rarDesc := fs.String("describe", "", "what this type authorises, for operators")
	credConfigs := fs.String("credential-configuration", "",
		"comma-separated credential_configuration_id values, as they appear in the "+
			"Credential Issuer's metadata (credential offer)")
	credIssuer := fs.String("credential-issuer", "",
		"the Credential Issuer identifier the wallet fetches metadata from. "+
			"Defaults to -issuer, which is right only when this deployment is both")
	credTxCode := fs.Bool("tx-code", false,
		"require a Transaction Code, delivered to the holder by another channel. "+
			"Defends against somebody photographing the QR code over their shoulder")
	credTxLength := fs.Int("tx-code-length", 6, "digits in the generated transaction code")
	credTTL := fs.Duration("offer-expires", 5*time.Minute,
		"how long the pre-authorized code lasts. Short by design: section 3.5 says "+
			"it MUST be short lived, and it is redeemed within seconds of being scanned")

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
	// The flow commands read a file and nothing else, for the same reason: a
	// flow that would not load must fail in CI, not on the next restart.
	case "flow test":
		return flowTest(*flowFile)
	case "flow paths":
		return flowPaths(*flowFile, *flowName)
	case "flow show":
		return flowShow()
	// The theme commands read files and nothing else. Dispatched here, before a
	// DSN is required, because validating a theme is something you do in CI --
	// where there is no database to reach and no reason to need one.
	case "theme check":
		return themeCheck(*themeDir)
	case "theme eject":
		return themeEject(*themeDir, *themeOnly, *themeForce)
	case "theme list":
		return themeList(*themeDir)
	// Same reasoning as the theme commands: files only, no database, so a
	// pipeline can refuse a half-translated catalogue before it is deployed.
	case "i18n list":
		return i18nList(*themeDir)
	case "i18n status":
		return i18nStatus(*themeDir)
	case "i18n keys":
		return i18nKeys(*themeDir)
	}

	// `outpost run` is the whole point of an outpost: it holds NO database
	// credentials. Dispatched before the DSN is required, because requiring one
	// would defeat the feature entirely.
	if cmd == "outpost run" {
		return outpostRun(*outpostCore, *outpostToken, *outpostKind, *addr, *ldapBaseDN)
	}

	// `kerberos check` needs no database. It answers "will this keytab work",
	// which is a question about files and clocks, and it must be runnable on the
	// machine that will serve SPNEGO before anything else is configured.
	if cmd == "kerberos check" {
		return kerberosCheck(*keytabPath, *krbRealm, *krbSPN)
	}
	// `kerberos principals` needs no database either: it asks the realm what it
	// holds, which is a question worth answering before deciding to sync it.
	if cmd == "kerberos principals" {
		pctx, pcancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer pcancel()
		return kerberosPrincipals(pctx, *krbRealm, *krbAdmin, *keytabPath)
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
	case "migrate fingerprint":
		return printFingerprint(ctx, conn)
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
			*tlsSANIP, *tlsSANEmail, *spCert, *tlsBound)
	case "erase subject":
		return eraseSubjectCmd(ctx, conn, *eraseSubject, *eraseConfirm, *eraseDeactivate)
	case "client set-assertion-issuers":
		return clientSetAssertionIssuers(ctx, conn, *clientID, *assertionIssuers)
	case "client set-exchange-containment":
		return clientSetExchangeContainment(ctx, conn, *clientID, *exchangeAudMatch)
	case "client set-dpop":
		return clientSetDPoP(ctx, conn, *clientID, *dpopBound)
	case "client set-hybrid":
		return clientSetHybrid(ctx, conn, *clientID, *reviewBy)
	case "client set-keys":
		return clientSetKeys(ctx, conn, *clientID, *jwksPath)
	case "client set-grants":
		return clientSetGrants(ctx, conn, *clientID, *grantTypes)
	case "client create":
		return clientCreate(ctx, conn, *clientID, *name, *redirect, *public,
			*launchURL, *logoURL, *portalHidden, *requirePKCE)
	case "serve":
		return serve(conn, *addr, *tlsCert, *tlsKey, *adminAddr, *adminInsecure)
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
	case "ssf add-source":
		return ssfAddSource(ctx, conn, *orgID, *name, *srcIssuer, *srcJWKS,
			*srcAudience, *ssfEvents, *ssfCritical)
	case "ssf received":
		return ssfReceived(ctx, conn, *orgID)
	case "ssf add-stream":
		return ssfAddStream(ctx, conn, *orgID, *clientID, *ssfEndpoint, *ssfToken, *ssfEvents, *ssfPoll)
	case "ssf list":
		return ssfListStreams(ctx, conn)
	case "provider add":
		return providerAdd(ctx, conn, *orgID, *providerHook, *providerURL,
			*providerMode, *providerTimeout)
	case "provider list":
		return providerList(ctx, conn, *orgID)
	case "provider remove":
		return providerRemove(ctx, conn, *orgID, *providerHook)
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
	case "keys retire":
		return keysRetire(ctx, conn, *dryRun)
	case "keys rewrap-root":
		return keysRewrapRoot(ctx, conn, *dryRun)
	case "saml add-sp":
		return samlAddSP(ctx, conn, *orgID, *entityID, *name, *acsURL, *nameIDFormat, *sloURL,
			*spCert, *wantSignedReq, *sloBinding, *spEncCert, *spKeyTransport)
	case "logout-test":
		return logoutTest(ctx, conn, *rpURL, *clientID, *issuer, *subject, *sidFlag)
	case "federation enable":
		return federationEnable(ctx, conn, *authorityHints, *orgName, *homepageURI)
	case "rar register":
		return rarRegister(ctx, conn, *orgID, *rarType, *rarFields, *rarRequired, *rarDesc)
	case "rar allow":
		return rarAllow(ctx, conn, *clientID, *rarType)
	case "rar list":
		return rarList(ctx, conn)
	case "credential define":
		return credentialDefine(ctx, conn, *orgID, *credConfigs, *credVCT,
			*credAlways, *credSelective, *credLifetime, *brandName)
	case "credential list":
		return credentialList(ctx, conn)
	case "credential offer":
		return credentialOffer(ctx, conn, *orgID, *email, *clientID, *credConfigs,
			*credIssuer, *issuer, *credTxCode, *credTxLength, *credTTL)
	case "federation show":
		return federationShow(ctx, conn)
	case "trust-mark issue":
		return trustMarkIssue(ctx, conn, *tmType, *tmSubject, *tmLogo, *tmRef,
			*tmDelegation, *tmLifetime)
	case "trust-mark revoke":
		return trustMarkRevoke(ctx, conn, *tmType, *tmSubject, *tmReason)
	case "trust-mark list":
		return trustMarkList(ctx, conn)
	case "trust-mark accept":
		return trustMarkAccept(ctx, conn, *tmFile)
	case "trust-mark drop":
		return trustMarkDrop(ctx, conn, *tmType, *tmIssuer)
	case "trust-mark delegate":
		return trustMarkDelegate(ctx, conn, *tmType, *tmDelegate, *tmRef, *tmLifetime)
	case "trust-mark issuers":
		return trustMarkIssuers(ctx, conn, *tmFile)
	case "trust-mark owners":
		return trustMarkOwners(ctx, conn, *tmFile)
	case "uma settings":
		return umaSettings(ctx, conn, *orgID, *umaIntervention, *umaPoll)
	case "uma requests":
		return umaRequests(ctx, conn, *orgID)
	case "uma approve":
		return umaApprove(ctx, conn, *umaRequestID, *relRelation)
	case "uma deny":
		return umaDeny(ctx, conn, *umaRequestID)
	case "client set-claims-redirects":
		return clientSetClaimsRedirects(ctx, conn, *clientID, *claimsRedirects)
	case "authz set-model":
		return authzModelSet(ctx, conn, *orgID, *modelFile)
	case "authz show-model":
		return authzModelShow(ctx, conn, *orgID)
	case "authz grant":
		return authzGrant(ctx, conn, *orgID, *relSubject, *relRelation, *relObject)
	case "authz revoke":
		return authzRevoke(ctx, conn, *orgID, *relSubject, *relRelation, *relObject)
	case "authz check":
		return authzCheck(ctx, conn, *orgID, *relSubject, *relAction, *relObject)
	case "events subscribe":
		return eventsSubscribe(ctx, conn, *orgID, *name, *subURL, *subEvents)
	case "events list":
		return eventsList(ctx, conn, *orgID)
	case "outpost create":
		return outpostCreate(ctx, conn, *orgID, *name, *outpostKind)
	case "outpost list":
		return outpostList(ctx, conn, *orgID)
	case "invite create":
		return inviteCreate(ctx, conn, *orgID, *email, *inviteGroups, *inviteTTL, *issuer)
	case "invite list":
		return inviteList(ctx, conn, *orgID)
	case "signup enable":
		return signupEnable(ctx, conn, *orgID, *signupDomains, *inviteGroups)
	case "signup disable":
		return signupDisable(ctx, conn, *orgID)
	case "signup show":
		return signupShow(ctx, conn, *orgID)
	case "kerberos sync":
		return kerberosSync(ctx, conn, *orgID, *krbRealm, *krbAdmin, *keytabPath, *apply)
	case "prompt set":
		return promptSet(ctx, conn, *orgID, *slug, *promptFile)
	case "prompt list":
		return promptList(ctx, conn, *orgID)
	case "plan":
		return configPlan(ctx, conn, *orgID, *configFile, *prune, false)
	case "apply":
		return configPlan(ctx, conn, *orgID, *configFile, *prune, true)
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
	case "idp apple-secret":
		return idpAppleSecret(ctx, conn, *slug, *appleTeam, *appleKeyID, *appleKeyFile)
	case "idp list":
		return idpList(ctx, conn)
	case "idp assertions":
		return idpAssertions(ctx, conn, *slug, *allowAssertions)
	case "idp add-issuer":
		return idpAddIssuer(ctx, conn, *orgID, *slug, *name, *issuer, *jwksURL)
	case "scim add":
		return scimAdd(ctx, conn, *orgID, *slug, *name, *baseURL, *scimToken, *onDeactivate, *dryRun2)
	case "provision add":
		return provisionAdd(ctx, conn, *orgID, *slug, *name, *outpostKind,
			*credsFile, *dirImpersonate, *targetDomain, *onDeactivate, *dryRun2)
	case "duo set":
		return duoSet(ctx, conn, *orgID, *duoClientID, *duoSecret, *duoAPIHost, *duoFailOpen)
	case "duo enroll":
		return duoEnroll(ctx, conn, *orgID, *email, *duoUsername)
	case "duo show":
		return duoShow(ctx, conn)
	case "attester add":
		return attesterAdd(ctx, conn, *orgID, *name, *attesterJWKS)
	case "attester list":
		return attesterList(ctx, conn)
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
	case "flow apply":
		return flowApply(ctx, conn, *orgID, *flowFile)
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
	instanceID, set, _, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}

	// Retired keys are not in the set and so are not listed. That is the same
	// answer the JWKS gives, which is the point of listing at all: this command
	// should show what relying parties can see.
	dwell, _, err := keys.RequiredPassiveDwell(ctx, conn, instanceID)
	if err != nil {
		return err
	}

	fmt.Printf("%-24s %-8s %-8s %-22s %s\n", "KID", "ALG", "STATE", "PUBLISHED", "NOTE")
	for _, k := range set.Keys() {
		note := ""
		switch k.State() {
		case keys.StateNext:
			if ok, wait := set.CanPromote(k); ok {
				note = "ready to promote"
			} else {
				note = fmt.Sprintf("promotable in %s", wait.Round(time.Minute))
			}
		case keys.StatePassive:
			if ok, wait := set.CanRetire(k, dwell); ok {
				note = "ready to retire"
			} else if k.DemotedAt().IsZero() {
				note = "no demotion time recorded; will not retire"
			} else {
				note = fmt.Sprintf("retirable in %s", wait.Round(time.Minute))
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

// keysRetire removes passive keys that nothing can still be verifying against.
//
// This is the last step of the rotation machine, and the one that was documented
// from the start and never built: passive keys stayed in the JWKS forever, so the
// published set grew with every rotation and no key ever left.
//
// There is deliberately no `-now`. `keys rotate -now` exists because signing with
// a compromised key is worse than some relying parties failing verification for a
// few hours, and the operator sees that failure immediately. Retiring early
// inverts both halves: it does not stop a compromised key being used -- demotion
// already did that -- and the damage lands on tokens already in the field,
// failing at verifiers this deployment does not run, weeks later. There is no
// emergency that early retirement solves, so the flag would only ever be a way to
// cause the problem the dwell exists to prevent.
// keysRewrapRoot re-seals every root-wrapped secret under a new root key.
//
// # The dry run is the important part
//
// `-dry-run` does the ENTIRE job — opens every blob with the old key, re-seals
// each with the new one, writes them all — and then rolls back. That is the only
// way to learn whether a rotation would succeed without betting the deployment
// on finding out. A dry run that merely counted rows would prove nothing about
// the one thing that can go wrong, which is a blob the current key cannot open.
//
// # Why the old key comes from the environment and the new one is separate
//
// SIGNARI_ROOT_KEY stays what it is: the key this deployment is running on. The
// replacement is SIGNARI_NEW_ROOT_KEY. Overloading one variable would mean the
// command could not tell "rotate to this" from "this is already the key", and
// the failure mode of guessing wrong is a database nothing opens.
//
// After a successful run, SIGNARI_ROOT_KEY must be set to the new value
// everywhere before any node restarts. A node that comes up holding the old key
// finds every row wrapped under a ref it does not have, and refuses to start --
// which is the designed outcome, not a bug: `LoadSet` compares `key_ref` against
// the configured key and says so, rather than failing later inside a signature.
func keysRewrapRoot(ctx context.Context, conn *pgx.Conn, dryRun bool) error {
	old, err := rootKey()
	if err != nil {
		return err
	}
	nextB64 := os.Getenv("SIGNARI_NEW_ROOT_KEY")
	if nextB64 == "" {
		return fmt.Errorf(
			"SIGNARI_NEW_ROOT_KEY is unset (32 random bytes, base64) -- generate one with:\n" +
				"  head -c 32 /dev/urandom | base64\n" +
				"and set SIGNARI_NEW_ROOT_KEY_REF to a name distinct from the current one")
	}
	next, err := keys.NewRootKeyFromBase64(os.Getenv("SIGNARI_NEW_ROOT_KEY_REF"), nextB64)
	if err != nil {
		return fmt.Errorf("the new root key: %w", err)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	// Rolled back on every path that does not explicitly commit, including a
	// panic. A half-rotated database is not a degraded state, it is one no
	// single key opens.
	defer func() { _ = tx.Rollback(ctx) }()

	reports, err := keys.RewrapRoot(ctx, tx, old, next)
	if err != nil {
		return err
	}

	var total, skipped int
	for _, r := range reports {
		total += r.Rows
		skipped += r.Skipped
		if r.Rows > 0 || r.Skipped > 0 {
			line := fmt.Sprintf("  %-40s %d re-wrapped", r.Table+"."+r.Column, r.Rows)
			if r.Skipped > 0 {
				line += fmt.Sprintf(", %d already under the new key", r.Skipped)
			}
			fmt.Println(line)
		}
	}

	if dryRun {
		fmt.Printf("\nDRY RUN: %d secrets would be re-wrapped from %q to %q. Nothing written.\n",
			total, old.Ref(), next.Ref())
		return nil
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing the rotation: %w", err)
	}
	fmt.Printf("\n%d secrets re-wrapped from %q to %q.\n", total, old.Ref(), next.Ref())
	fmt.Println("\nSet SIGNARI_ROOT_KEY to the new value on EVERY node before any of them")
	fmt.Println("restarts. A node holding the old key will refuse to start rather than")
	fmt.Println("serve with keys it cannot open. Keep the old key until every node has")
	fmt.Println("been restarted on the new one and a restore test has passed.")
	return nil
}

func keysRetire(ctx context.Context, conn *pgx.Conn, dryRun bool) error {
	instanceID, set, _, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}

	dwell, why, err := keys.RequiredPassiveDwell(ctx, conn, instanceID)
	if err != nil {
		return err
	}
	fmt.Printf("Passive keys must stay published for %s (%s).\n", dwell, why)

	var eligible []keys.Key
	var waiting int
	for _, k := range set.Keys() {
		if k.State() != keys.StatePassive {
			continue
		}
		ok, wait := set.CanRetire(k, dwell)
		switch {
		case ok:
			eligible = append(eligible, k)
		case k.DemotedAt().IsZero():
			// Refused rather than retired. See CanRetire: a missing stamp must
			// not read as "demoted at the zero time", which would retire it now.
			fmt.Printf("%s (%s): passive but has no demotion time recorded; not retiring it.\n",
				k.KID(), k.Algorithm())
			waiting++
		default:
			fmt.Printf("%s (%s): retirable in %s.\n",
				k.KID(), k.Algorithm(), wait.Round(time.Minute))
			waiting++
		}
	}

	if len(eligible) == 0 {
		if waiting == 0 {
			fmt.Println("No passive keys. Nothing to retire.")
		}
		return nil
	}

	if dryRun {
		for _, k := range eligible {
			fmt.Printf("%s (%s): would be retired (demoted %s).\n",
				k.KID(), k.Algorithm(), k.DemotedAt().UTC().Format(time.RFC3339))
		}
		fmt.Printf("Dry run: %d key(s) would leave the JWKS. Nothing changed.\n", len(eligible))
		return nil
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, k := range eligible {
		if err := keys.Retire(ctx, tx, instanceID, k.KID(), dwell); err != nil {
			return err
		}
		fmt.Printf("%s (%s): retired. It leaves the JWKS at the next restart or config reload.\n",
			k.KID(), k.Algorithm())
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

func serve(conn *pgx.Conn, addr, tlsCert, tlsKey, adminAddr string, adminInsecure bool) error {
	// Cancelled on SIGINT or SIGTERM, which is what an orchestrator sends before
	// it eventually kills the process. Everything started below hangs off this
	// context, so the signal reaches the background workers as well as the
	// listeners -- the outbox and janitor loops stop taking new work instead of
	// being terminated mid-transaction.
	ctx, stopSignals := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
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
	srv.SetInstance(instanceID)
	// Needed to unseal personal user attributes for operator-defined claims.
	srv.SetRootKey(root)

	// OpenID Federation keys, loaded only if this instance has any.
	//
	// A deployment that is not in a federation has none, and that is the
	// ordinary case: SetFederationKeys(nil) leaves the configuration endpoint
	// unregistered rather than serving an Entity Configuration nobody asked for.
	if fedSet, ferr := keys.LoadSetFor(ctx, conn, instanceID, keys.PurposeFederation, root); ferr == nil &&
		len(fedSet.JWKS().Keys) > 0 {
		srv.SetFederationKeys(fedSet)
		log.Info("openid federation enabled", "keys", len(fedSet.JWKS().Keys))
	}
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
	// Every audited event fans out to event subscriptions, in the transaction
	// that wrote it. Installed once, here, so no code path can record an event
	// without it being publishable.
	audit.SetPublisher(store.AuditPublisher)

	go outbox.New(pool, set, issuer, root, log).Run(workerCtx, 2*time.Second)

	// The janitor is likewise a singleton, but it enforces that itself with an
	// advisory lock rather than by convention -- so it is safe to start on every
	// node, and there is no separate unit an operator can forget to deploy. The
	// jobs it runs are the ones whose absence is invisible until it matters:
	// relying parties never told a session ended, and a table that only grows.
	go janitor.Run(workerCtx, pool, log, janitor.DefaultInterval)

	// Audit streaming to a logically separate system (ASVS V16.4.3), off unless a
	// destination is configured. Forwarding authentication events off the box is a
	// data-residency decision, so it happens only when an operator names where.
	if sink, serr := auditsink.NewFromEnv(os.Getenv, log); serr != nil {
		return fmt.Errorf("audit streaming: %w", serr)
	} else if sink != nil {
		go auditsink.NewPump(pool, sink, log).Run(workerCtx, 10*time.Second)
	}

	// Authenticator model resolution (AAGUID -> "YubiKey 5 NFC"), off unless a
	// FIDO metadata source is configured. Display only, so a nil resolver is a
	// silent fall-back to passkey nicknames rather than a startup failure; when
	// present it refreshes in the background like the other singletons.
	models := fidomds.NewFromEnv(os.Getenv, log)
	srv.SetAuthenticatorModels(models)
	if models != nil {
		go models.Run(workerCtx, fidomds.DefaultRefresh)
	}

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
		// Personal user attributes are sealed under the subject's key, so the
		// attribute routes need the key that unwraps subject keys. Without it
		// they are not registered at all.
		adminSrv.SetRootKey(root)

		// Refused at startup, not warned about at runtime.
		//
		// Every request to this listener carries a bearer token that can create a
		// client, reset a password or erase a subject. Serving that in clear is
		// not a degraded mode, it is a credential disclosure on every call, and
		// the operator who would notice a log line is not the one who needs the
		// message.
		if tlsCert == "" && !adminInsecure {
			return fmt.Errorf("the admin API will not serve plaintext: pass -tls-cert " +
				"and -tls-key, or -admin-insecure if it is bound to loopback behind a " +
				"terminator you control")
		}

		go func() {
			scheme := "https"
			if tlsCert == "" {
				scheme = "http"
			}
			log.Info("admin API listening", "addr", adminAddr, "scheme", scheme)
			ah := &http.Server{
				Addr:              adminAddr,
				Handler:           adminSrv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			// Shut down with the rest of the process rather than being killed
			// with it. An admin write is a transaction that bumps the config
			// version; losing one halfway is a durable write whose caller never
			// learned whether it happened.
			go func() {
				<-ctx.Done()
				sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout())
				defer cancel()
				if err := ah.Shutdown(sctx); err != nil {
					log.Error("admin API shutdown", "err", err)
				}
			}()
			var err error
			if tlsCert != "" {
				err = ah.ListenAndServeTLS(tlsCert, tlsKey)
			} else {
				err = ah.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		ldapHasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
		// SIGNARI_LDAP_WRITE_GROUP names who may Add, Modify, Delete and Modify
		// DN. Empty means nobody, and the directory stays read-only exactly as it
		// was -- see internal/ldapd/write.go for why that is two decisions rather
		// than one.
		ldapWriteGroup := os.Getenv("SIGNARI_LDAP_WRITE_GROUP")
		ldapSrv := ldapd.New(ldapd.Config{
			BaseDN:   baseDN,
			UserAttr: envOr("SIGNARI_LDAP_USER_ATTR", "uid"),
			// Anonymous search stays off unless asked for: it publishes a user
			// directory to anyone who can reach the port.
			AllowAnonymousSearch: os.Getenv("SIGNARI_LDAP_ANONYMOUS_SEARCH") == "1",
			WriteGroup:           ldapWriteGroup,
		}, httpapi.NewLDAPAuthenticator(pool, ldapHasher, ldapOrgID, log), log)

		if ldapWriteGroup != "" {
			ldapSrv = ldapSrv.WithWriter(httpapi.NewLDAPWriter(pool, ldapHasher,
				passwords.PolicyFromEnv(), ldapOrgID, log))
			// Said out loud at startup, at Warn. This turns a read-only bind shim
			// into something that can create accounts and set passwords, and the
			// only other evidence an operator has is one environment variable they
			// may not have set themselves.
			log.Warn("LDAP writes are ENABLED",
				"write_group", ldapWriteGroup,
				"note", "members of this group may add, modify, rename and DELETE "+
					"directory entries, and may set any password")
		}

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
				passwords.NewHasher(passwords.MemoryBudgetMiB), radiusOrgID, log), log)
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

	// Metrics.
	//
	// On its own listener, off unless an address is given, exactly like the admin
	// API. Serving them from the public listener would publish request rates,
	// error rates and sign-in failure counts to anybody who can reach the sign-in
	// page -- which is, for an identity provider, the whole internet. Those are
	// not secrets individually and together they are a map of the deployment:
	// when it is busiest, when it is degraded, and whether an attack is working.
	//
	// A separate address also means the usual advice ("bind it to the internal
	// network") is something an operator can actually follow, rather than being
	// told to put a path exception in a proxy.
	metricsAddr := os.Getenv("SIGNARI_METRICS_ADDR")
	if metricsAddr != "" {
		// Built only when it will be served. Instrumenting a process nobody can
		// scrape is work done for nothing, and the nil case is what keeps the
		// middleware out of Routes() entirely.
		met := metrics.NewEngine()
		srv.SetMetrics(met)
		go func() {
			mm := http.NewServeMux()
			mm.Handle("GET /metrics", met.Handler())
			mh := &http.Server{
				Addr:              metricsAddr,
				Handler:           mm,
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func() {
				<-ctx.Done()
				sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout())
				defer cancel()
				_ = mh.Shutdown(sctx)
			}()
			log.Info("metrics listening", "addr", metricsAddr)
			if err := mh.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics listener stopped", "err", err)
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

	// Ordered shutdown. The sequence is the whole point, and getting it wrong is
	// invisible until a deploy drops requests:
	//
	//  1. Mark the node NOT READY. `/readyz` starts answering 503 while the
	//     listener is still accepting, so a load balancer has a window to take
	//     this node out of rotation.
	//  2. Wait out that window. Shutting down immediately means the socket
	//     closes before anything upstream has noticed, and every request routed
	//     here in the meantime is refused -- the drain window becomes the error
	//     window. This is the step people leave out.
	//  3. Stop accepting and let in-flight requests finish, bounded.
	//
	// A signing operation or a token exchange interrupted at step 3 is a client
	// that gets a connection reset for a request the database may already have
	// committed, which is the ambiguity refresh-token rotation exists to avoid
	// creating.
	go func() {
		<-ctx.Done()
		log.Info("shutting down", "drain", shutdownDrain(), "timeout", shutdownTimeout())
		srv.BeginDraining()

		// Never drain for longer than the whole budget. A deployment that sets
		// the drain above the timeout means to wait a long time, not to spend
		// the entire grace period unready and then be SIGKILLed mid-request.
		drain := shutdownDrain()
		if drain > shutdownTimeout() {
			drain = shutdownTimeout()
		}
		time.Sleep(drain)

		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout())
		defer cancel()
		if err := h.Shutdown(sctx); err != nil {
			// Reported, not swallowed: this is the difference between "every
			// request finished" and "the timeout expired and some did not".
			log.Error("shutdown did not complete cleanly", "err", err)
		}
	}()

	if tlsCert == "" || tlsKey == "" {
		log.Info("serving over plaintext HTTP", "addr", addr, "issuer", issuer,
			"algs", set.Algorithms())
		log.Warn("no TLS configured: browsers will refuse to store the __Host- session " +
			"cookie over plaintext on any host except localhost, so sign-in will silently " +
			"fail to persist. Supply -tls-cert and -tls-key outside local testing.")
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
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
	if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// shutdownDrain is how long to keep serving after being told to stop.
//
// The default is five seconds because that is longer than the interval of every
// common readiness probe, which is what the window exists to outlast: the node
// must be observed unready by whatever routes to it before it stops listening.
// Zero disables the wait, which is right for a local run and wrong behind a load
// balancer.
func shutdownDrain() time.Duration {
	return durationEnv("SIGNARI_SHUTDOWN_DRAIN", 5*time.Second)
}

// shutdownTimeout bounds how long in-flight requests may take to finish.
//
// Twenty seconds by default: long enough for a slow token exchange or an
// outbound back-channel logout, short enough to stay inside the grace period an
// orchestrator allows before it sends SIGKILL. Set it under that grace period,
// never above -- a timeout longer than the one that kills you is a timeout that
// never runs.
func shutdownTimeout() time.Duration {
	return durationEnv("SIGNARI_SHUTDOWN_TIMEOUT", 20*time.Second)
}

// durationEnv reads a Go duration, falling back rather than failing.
//
// A malformed value is logged and ignored. This is read on the shutdown path,
// where refusing to start over a typo in a timeout would be a worse outcome than
// using the default -- and where returning an error has nowhere to go.
func durationEnv(name string, fallback time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		slog.Warn("ignoring a malformed duration", "var", name, "value", raw,
			"using", fallback)
		return fallback
	}
	return d
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

// printFingerprint writes the live schema digest and nothing else.
//
// # Why this exists separately from `migrate status`
//
// It is for a build script, and a build script cannot parse prose. `migrate
// status` prints the version, the pending list and the fingerprint in a layout
// meant for a person; anything capturing the digest from it would be one cosmetic
// change away from pinning a binary to the string "pending" -- and the failure
// would be a fingerprint mismatch at every boot, which reads as schema drift
// rather than as a broken build.
//
// One value, no label, no trailing prose. `$(signari migrate fingerprint)` is the
// whole contract.
func printFingerprint(ctx context.Context, conn *pgx.Conn) error {
	fp, err := migrate.Fingerprint(ctx, conn)
	if err != nil {
		return err
	}
	fmt.Println(fp)
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
	// The same gate the web paths use. The CLI creates the FIRST user of a
	// deployment -- the account with the most access and the longest life -- so
	// it is the last place a weaker rule belongs.
	if _, perr := passwords.PolicyFromEnv().Check(ctx, password, email, nil, hasher); perr != nil {
		return perr
	}
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
	public bool, launchURL, logoURL string, portalHidden, requirePKCE bool) error {

	if err := clients.ValidateClientID(clientID); err != nil && clientID != "" {
		return err
	}
	if clientID == "" || redirect == "" {
		return fmt.Errorf("-client-id and -redirect are both required")
	}
	// Checked before it reaches the database. A redirect URI carrying a
	// response parameter is a trap for whichever relying party reads the first
	// occurrence -- see internal/clients/redirect.go.
	if err := clients.ValidateRedirectURI(redirect); err != nil {
		return err
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
		// Ours are 256 bits of random data, so entropy is the property that
		// protects them -- not the cost of the hash. See internal/clients.
		if fast, ok := clients.HashSecret(secret); ok {
			secretHash = fast
		} else if secretHash, err = hasher.Hash(ctx, secret); err != nil {
			return err
		}
	}

	// client_id is settable verbatim so an existing relying party's configuration
	// does not have to change during a migration.
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, scopes,
		                          initiate_login_uri, logo_uri, portal_hidden,
		                          require_pkce)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''),
		        ARRAY['openid','profile','email','offline_access'],
		        NULLIF($6,''), NULLIF($7,''), $8, $9)`,
		clientID, orgID, name, kind, secretHash,
		launchURL, logoURL, portalHidden, requirePKCE); err != nil {
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
		       allow_jwt_bearer,
		       (SELECT count(*) FROM core.federated_identities f WHERE f.provider_id = p.id)
		FROM core.identity_providers p ORDER BY slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-14s %-12s %-8s %-8s %-8s %-10s %s\n",
		"SLUG", "KIND", "SIGNUP", "LINKING", "ENABLED", "ASSERTIONS", "LINKED ACCOUNTS")
	var n int
	for rows.Next() {
		var slug, name, kind string
		var signup, linking, enabled, assertions bool
		var linked int
		if err := rows.Scan(&slug, &name, &kind, &signup, &linking, &enabled,
			&assertions, &linked); err != nil {
			return err
		}
		n++
		fmt.Printf("%-14s %-12s %-8t %-8t %-8t %-10t %d\n",
			slug, kind, signup, linking, enabled, assertions, linked)
	}
	if n == 0 {
		fmt.Println("(none registered -- add one with `signari idp add`)")
	}
	return rows.Err()
}

// eraseSubjectCmd crypto-shreds a subject.
//
// # The confirmation carries information on purpose
//
// It is not a -yes or a -force. The operator has to repeat the subject uuid, so
// the confirmation cannot be satisfied by muscle memory or by a flag pasted from
// a runbook -- the thing being confirmed is WHICH subject, and that is the only
// mistake this command can make that nobody can undo.
//
// The account's email address is printed before the destruction, for the same
// reason: a prompt that cannot say whose data is at stake is a prompt people
// learn to answer without reading.
func eraseSubjectCmd(ctx context.Context, conn *pgx.Conn, subjectID, confirm string, deactivate bool) error {
	if subjectID == "" {
		return fmt.Errorf("-subject-id is required (the subject uuid to erase)")
	}
	if confirm == "" {
		// Shown, not just refused. An operator who has to go and find the syntax
		// reads it; one who is told "add -confirm" pastes it.
		return fmt.Errorf("erasure is permanent and cannot be undone. To proceed, "+
			"repeat the subject:\n  signari erase subject -subject-id %s -confirm %s",
			subjectID, subjectID)
	}
	if confirm != subjectID {
		return fmt.Errorf("-confirm does not match -subject-id, so this would have erased "+
			"a different subject than the one confirmed:\n  -subject-id %s\n  -confirm %s",
			subjectID, confirm)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rep, err := store.EraseSubject(ctx, tx, subjectID, deactivate)
	switch {
	case errors.Is(err, store.ErrSubjectUnknown):
		return fmt.Errorf("no subject key exists for %s. Nothing was erased -- and "+
			"nothing of theirs was ever encrypted with a subject key, so there is "+
			"nothing here to destroy", subjectID)
	case errors.Is(err, store.ErrAlreadyErased):
		// Not an error worth failing on in principle, but worth saying: an
		// operator repeating an erasure wants to know it already happened rather
		// than to be told "done" twice.
		return fmt.Errorf("%s was already erased. The earlier erasure stands; "+
			"nothing changed", subjectID)
	case errors.Is(err, store.ErrSubjectStillActive):
		return fmt.Errorf("%s (%s) is still active.\n\n"+
			"An erased subject can never hold a key again, so an active account "+
			"whose key is destroyed does not work with less data -- it fails, "+
			"permanently, in ways that look like bugs.\n\n"+
			"Either deactivate it first, or say so here:\n"+
			"  signari erase subject -subject-id %s -confirm %s -deactivate",
			subjectID, describeAccount(rep), subjectID, subjectID)
	case err != nil:
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("erased %s%s\n", subjectID, func() string {
		if rep.Email != "" {
			return " (" + rep.Email + ")"
		}
		return ""
	}())
	fmt.Printf("  their data-encryption key is destroyed; everything sealed with it\n" +
		"  is permanently unreadable, including from backups\n")
	if rep.TOTPCredentials > 0 {
		fmt.Printf("  %d TOTP credential(s) are now unreadable\n", rep.TOTPCredentials)
	}
	if rep.Deactivated {
		fmt.Printf("  the account was deactivated in the same transaction\n")
	}
	if !rep.AccountFound {
		fmt.Printf("  no account exists for this subject; the key outlived it, which is\n" +
			"  why erasure is keyed on the subject rather than on the account\n")
	}
	fmt.Printf("  the subject_keys row survives with erased_at set: it is the evidence\n" +
		"  that the erasure happened and when\n")
	return nil
}

// describeAccount names an account for an error message without printing more
// than is needed to identify it.
func describeAccount(rep *store.ErasureReport) string {
	if rep == nil || rep.Email == "" {
		return "no email on record"
	}
	return rep.Email
}

// clientSetAssertionIssuers pairs a client with the issuers it may use.
//
// # Why this exists separately from registering the grant
//
// Registering a client for `urn:ietf:params:oauth:grant-type:jwt-bearer` says it
// may use the grant. It does not say WHOSE assertions it may use, and in an
// organisation that trusts more than one issuer those are different questions: a
// client that exists to let one CI pipeline reach one API should not be able to
// spend a Kubernetes pod's service-account token because both issuers happen to
// be configured in the same organisation.
//
// An empty list permits NOTHING, which is why this command exists at all -- a
// client registered for the grant and paired with nobody cannot use it, and that
// is the intended default for every client that predates this.
func clientSetAssertionIssuers(ctx context.Context, conn *pgx.Conn, clientID, list string) error {
	if clientID == "" {
		return fmt.Errorf("-client-id is required")
	}

	// Non-nil, and that is load-bearing rather than style. A nil slice is
	// encoded as SQL NULL, and the column is NOT NULL -- so clearing the list,
	// which is the one operation an operator reaches for in a hurry, failed with
	// a constraint violation. The unit tests never saw it because they set the
	// column through SQL directly; only running the command did.
	slugs := []string{}
	for _, sl := range strings.Split(list, ",") {
		if sl = strings.TrimSpace(sl); sl != "" {
			slugs = append(slugs, sl)
		}
	}

	// The client's organisation, so the slugs can be checked against providers
	// that actually exist in it. A typo here produces a client that is refused at
	// runtime with a message that deliberately explains nothing -- the grant's
	// refusals are uniform so they cannot be used to enumerate issuers -- so the
	// mistake has to be caught here or not at all.
	var orgID string
	if err := conn.QueryRow(ctx,
		`SELECT org_id::text FROM core.clients WHERE client_id = $1`, clientID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no client %q", clientID)
		}
		return err
	}

	for _, sl := range slugs {
		var enabled, allowed bool
		err := conn.QueryRow(ctx, `
			SELECT enabled, allow_jwt_bearer FROM core.identity_providers
			WHERE org_id = $1::uuid AND slug = $2`, orgID, sl).Scan(&enabled, &allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no identity provider %q in this client's organisation; "+
				"`signari idp list` shows the registered ones", sl)
		}
		if err != nil {
			return err
		}
		// Reported, not refused. The operator may legitimately be pairing ahead
		// of enabling, and refusing would force them to do it in an order the
		// tool chose.
		if !allowed {
			fmt.Printf("NOTE: %s does not accept assertions yet. Allow it with:\n"+
				"  signari idp assertions -slug %s -allow-assertions\n", sl, sl)
		}
		if !enabled {
			fmt.Printf("NOTE: %s is disabled, so nothing from it will be accepted.\n", sl)
		}
	}

	tag, err := conn.Exec(ctx, `
		UPDATE core.clients SET jwt_bearer_providers = $2, updated_at = now()
		WHERE client_id = $1`, clientID, slugs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}

	if len(slugs) == 0 {
		fmt.Printf("%s may no longer exchange assertions from any issuer.\n", clientID)
		return nil
	}
	fmt.Printf("%s may exchange assertions from: %s\n", clientID, strings.Join(slugs, ", "))
	return nil
}

// idpAddIssuer registers an issuer that only publishes signing keys.
//
// # Why this is not `idp add`
//
// `idp add` discovers a generic OIDC provider and refuses one whose discovery
// document names no authorization or token endpoint. That is correct for
// interactive sign-in, and it makes the most important class of RFC 7523 issuer
// impossible to register:
//
//	$ signari idp add -kind oidc -issuer https://token.actions.githubusercontent.com
//	signari: discovering ...: the discovery document names no authorization or
//	         token endpoint
//
// GitHub Actions, Kubernetes service-account issuers and SPIFFE bundles have no
// such endpoints and never will. They publish a JWKS. There is nothing to
// redirect a browser to.
//
// So they get their own command, exactly as an upstream SAML provider does, and
// the row it writes can never become a sign-in option: the schema refuses
// allow_signup and allow_linking on this kind, and the loader the interactive
// path uses refuses the kind outright.
func idpAddIssuer(ctx context.Context, conn *pgx.Conn, orgID, slug, name, issuer, jwks string) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this issuer belongs to")
	case slug == "":
		return fmt.Errorf("give -slug, a short name for this issuer")
	case issuer == "":
		return fmt.Errorf("give -issuer, the exact value assertions carry in `iss`")
	case jwks == "":
		return fmt.Errorf("give -jwks, the URL publishing this issuer's signing keys")
	}
	if name == "" {
		name = slug
	}

	// Fetched now, so a wrong URL fails in front of the person who typed it
	// rather than at the first grant -- the same reason `idp add` discovers
	// immediately. A trust anchor whose keys cannot be read is not a trust
	// anchor, it is a provider that refuses everything for a reason nobody can
	// see from the outside.
	set, err := federation.FetchJWKS(ctx, &http.Client{Timeout: 15 * time.Second}, jwks)
	if err != nil {
		return fmt.Errorf("reading %s: %w", jwks, err)
	}
	fmt.Printf("read %d key(s) from %s\n", len(set.Keys), jwks)

	var id string
	err = conn.QueryRow(ctx, `
		INSERT INTO core.identity_providers
			(org_id, slug, display_name, kind, client_id, issuer, jwks_url,
			 allow_signup, allow_linking, enabled, allow_jwt_bearer)
		VALUES ($1::uuid, $2, $3, 'assertion', '', $4, $5, false, false, true, false)
		RETURNING id::text`, orgID, slug, name, issuer, jwks).Scan(&id)
	if err != nil {
		return fmt.Errorf("registering the issuer: %w", err)
	}

	fmt.Printf("registered %s as an assertion issuer for %s\n", slug, issuer)
	// Off, and said out loud. Registering trust and granting it are two
	// decisions, and this command only makes the first.
	fmt.Printf("\nAssertions from it are NOT yet accepted. To allow them:\n"+
		"  signari idp assertions -slug %s -allow-assertions\n", slug)
	fmt.Printf("\nEach assertion's `sub` must also be linked to a local account before\n" +
		"it can mint anything.\n")
	return nil
}

// idpAssertions turns the RFC 7523 jwt-bearer grant on or off for one provider.
//
// Separate from `idp add` because it is a separate decision. Registering a
// provider says a person may sign in through it in a browser. This says any JWT
// that provider signs, presented by a client with nobody present, mints our
// tokens for the linked account -- which is a great deal more power, and an
// operator who set up "sign in with Google" did not ask for it.
//
// So it is off until somebody runs this, and the confirmation says what was
// granted rather than just "ok".
func idpAssertions(ctx context.Context, conn *pgx.Conn, slug string, allow bool) error {
	if slug == "" {
		return fmt.Errorf("-slug is required")
	}
	var issuer, jwks string
	var enabled bool
	err := conn.QueryRow(ctx, `
		UPDATE core.identity_providers SET allow_jwt_bearer = $2, updated_at = now()
		WHERE slug = $1
		RETURNING COALESCE(issuer,''), COALESCE(jwks_url,''), enabled`,
		slug, allow).Scan(&issuer, &jwks, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no identity provider called %q", slug)
	}
	if err != nil {
		return err
	}

	if !allow {
		fmt.Printf("%s: assertions refused. Its JWTs can no longer be exchanged for tokens.\n", slug)
		return nil
	}

	fmt.Printf("%s: assertions allowed. JWTs it signs may now be exchanged for our tokens\n"+
		"  by any client registered for the jwt-bearer grant, on behalf of the local\n"+
		"  account each assertion's subject is linked to.\n", slug)

	// Two conditions that make the switch inert, reported rather than left for
	// somebody to discover through a grant that silently never works.
	if !enabled {
		fmt.Printf("  NOTE: %s is currently disabled, so nothing will be accepted from it\n"+
			"  until it is enabled.\n", slug)
	}
	if jwks == "" {
		// For a named kind the JWKS URL comes from the preset, so an empty column
		// is only a problem for generic OIDC providers.
		var kind string
		if err := conn.QueryRow(ctx,
			`SELECT kind FROM core.identity_providers WHERE slug = $1`, slug).Scan(&kind); err == nil &&
			kind == "oidc" {
			fmt.Printf("  WARNING: %s has no jwks_url, so no assertion from it can be\n"+
				"  verified and every attempt will be refused.\n", slug)
		}
	}
	if issuer == "" {
		var kind string
		if err := conn.QueryRow(ctx,
			`SELECT kind FROM core.identity_providers WHERE slug = $1`, slug).Scan(&kind); err == nil &&
			kind == "oidc" {
			fmt.Printf("  WARNING: %s has no issuer configured, so no assertion can be\n"+
				"  matched to it.\n", slug)
		}
	}
	return nil
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
		// Verification is SCIM-specific: it checks a server's ServiceProviderConfig
		// and filter behaviour, neither of which a native target has.
		if t.Kind != "" && t.Kind != "scim" {
			fmt.Printf("%s: %s targets are written through their own API and have "+
				"no SCIM surface to verify\n", t.Slug, t.Kind)
			continue
		}
		rep, err := scim.Verify(ctx, scim.NewClient(t, hc), expected, nil)
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
		client, perr := provision.ForTarget(t, hc)
		if perr != nil {
			return perr
		}
		var created, deactivated, deleted, failed int

		for _, d := range desired {
			switch {
			case d.RemoteID == "" && d.Active:
				if !apply {
					created++
					continue
				}
				id, err := client.CreateUser(ctx, provision.User{
					ExternalID:  d.UserID,
					UserName:    d.UserName,
					DisplayName: d.DisplayName,
					Email:       d.Email,
					Active:      true,
				})
				if err != nil {
					// A conflict means the account is already there; find it and
					// record its id rather than creating a duplicate or giving up.
					var se *scim.Error
					if errors.As(err, &se) && se.Conflict {
						if found, ferr := client.FindByUserName(ctx, d.UserName); ferr == nil && found != nil {
							id = found.RemoteID
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

// flowTest checks a sign-in flow file without deploying it.
//
// The same load path the engine uses, so "it passes here" and "it will load"
// are the same statement. Passing means three things, and the output says all
// three because an operator who only reads "ok" learns the least useful one:
// the file parses, its own test cases hold, and the static safety analysis
// found no journey that issues a session without proving the subject.
func flowTest(path string) error {
	if path == "" {
		return fmt.Errorf("give -flow-file, the flow file to check")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	f, err := flow.Parse(data)
	if err != nil {
		return err
	}
	fmt.Printf("\n  %s: %s\n", path, f.Summary())
	for i := range f.Flows {
		fl := &f.Flows[i]
		fmt.Printf("\n  %s (%s)\n", fl.Name, fl.On)
		if !fl.On.Driven() {
			fmt.Printf("    !!   this engine has no %s journey, so nothing consults "+
				"this flow.\n         It parses, its safety rules apply and its tests "+
				"run. Deleting an\n         account is `signari erase subject` and the "+
				"admin API, which are\n         operator actions rather than a sequence "+
				"a subject walks.\n", fl.On)
		}
		for _, tc := range fl.Tests {
			fmt.Printf("    ok   %s\n", tc.Name)
		}
		paths, perr := fl.Paths()
		if perr != nil {
			fmt.Printf("    --   %v\n", perr)
			continue
		}
		fmt.Printf("    %d distinct journeys, every one of them proving the subject\n",
			len(paths))
	}
	fmt.Println("\n  This file will load. Its flows do what its tests say, and none of")
	fmt.Println("  them can issue a session without proving who the subject is.")
	return nil
}

// flowPaths lists every journey a flow admits.
//
// The point of the command: a flow file is read one step at a time and lived
// one journey at a time, and the gap between those two readings is where a
// misconfiguration hides. Enumerating removes the gap -- there is nothing left
// to infer.
func flowPaths(path, only string) error {
	var f *flow.File
	var err error
	if path == "" {
		// No file given: show the built-in flows, which is what a deployment is
		// running if nobody has written their own.
		if f, err = flow.Default(); err != nil {
			return err
		}
		fmt.Printf("\n  the built-in flows (no -flow-file given)\n")
	} else {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", path, rerr)
		}
		if f, err = flow.Parse(data); err != nil {
			return err
		}
		fmt.Printf("\n  %s\n", path)
	}

	shown := 0
	for i := range f.Flows {
		fl := &f.Flows[i]
		if only != "" && fl.Name != only {
			continue
		}
		shown++
		fmt.Printf("\n  %s (%s)\n", fl.Name, fl.On)
		paths, perr := fl.Paths()
		if perr != nil {
			return perr
		}
		for _, p := range paths {
			var when []string
			for _, c := range fl.Conditions() {
				if p.Given[c] {
					when = append(when, c)
				}
			}
			situation := "nothing in particular"
			if len(when) > 0 {
				situation = strings.Join(when, ", ")
			}
			var names []string
			for _, st := range p.Stages {
				names = append(names, string(st))
			}
			fmt.Printf("    %-58s  %s\n", strings.Join(names, " -> "), situation)
		}
	}
	if shown == 0 {
		return fmt.Errorf("no flow named %q in that file", only)
	}
	return nil
}

// flowApply installs a sign-in flow file.
func flowApply(ctx context.Context, conn *pgx.Conn, orgID, path string) error {
	if orgID == "" || path == "" {
		return fmt.Errorf("give -org and -flow-file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// Parsed BEFORE storing, which here means more than it does for a policy: a
	// document that reaches the table has had its own test cases run AND has been
	// proved unable to issue a session without authenticating somebody. Storing
	// first and validating at load would put a document the engine will refuse
	// into a table an operator already believes is deployed.
	f, err := flow.Parse(data)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.sign_in_flows (org_id, document)
		VALUES ($1::uuid, $2)
		ON CONFLICT (org_id) DO UPDATE
			SET document = EXCLUDED.document, applied_at = now()`,
		orgID, string(data)); err != nil {
		return err
	}
	fmt.Printf("applied %s (%s)\n", path, f.Summary())
	warnUndriven(f)
	// The journeys, not just the count. An operator has just changed how every
	// person in this organisation signs in, and this is the moment to show them
	// what they changed it to.
	for i := range f.Flows {
		fl := &f.Flows[i]
		paths, perr := fl.Paths()
		if perr != nil {
			continue
		}
		fmt.Printf("\n  %s (%s) -- %d journeys\n", fl.Name, fl.On, len(paths))
		for _, pth := range paths {
			var names []string
			for _, st := range pth.Stages {
				names = append(names, string(st))
			}
			fmt.Printf("    %s\n", strings.Join(names, " -> "))
		}
	}
	return nil
}

// flowShow prints the built-in flows verbatim, as a file to start from.
func flowShow() error {
	// Parsed before it is printed, so the command cannot hand somebody a file
	// that would not load if they saved it.
	if _, err := flow.Default(); err != nil {
		return err
	}
	fmt.Print(string(flow.DefaultDocument()))
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
	token, events string, poll bool) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid this receiver belongs to")
	case clientID == "":
		return fmt.Errorf("give -client, the relying party this stream is for")
	}
	// A poll stream is pulled, not pushed: it has no endpoint of ours to POST to,
	// and the receiver authenticates to us as its OAuth client rather than with a
	// token we would push. So the two push-only flags are refused here rather than
	// silently ignored -- a stored endpoint nobody reads is a misconfiguration
	// waiting to look like a delivery bug.
	if poll {
		if endpoint != "" {
			return fmt.Errorf("a -poll stream has no -endpoint: the receiver pulls from " +
				"POST /ssf/poll, authenticating as its client. Drop -endpoint")
		}
		if token != "" {
			return fmt.Errorf("a -poll stream has no -receiver-token: the receiver " +
				"authenticates to us with its client credentials when it polls. Drop " +
				"-receiver-token")
		}
	} else {
		if endpoint == "" {
			return fmt.Errorf("give -endpoint, the https URL to push Security Event " +
				"Tokens to (or -poll for a stream the receiver pulls from)")
		}
		if !strings.HasPrefix(endpoint, "https://") {
			return fmt.Errorf("the endpoint must be https: %q would carry security events "+
				"about real users across the network in the clear", endpoint)
		}
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

	method := "push"
	var endpointCol any = endpoint
	if poll {
		method = "poll"
		endpointCol = nil
	}

	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url,
		                              auth_token, events_requested)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		RETURNING id::text`, orgID, clientID, method, endpointCol, sealed, list).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("client %q already has a stream; one receiver per relying "+
				"party", clientID)
		}
		return err
	}

	if poll {
		fmt.Printf("registered a POLL stream for %s\n  events   : %s\n",
			clientID, strings.Join(list, ", "))
		fmt.Println("\n  The receiver pulls its events from POST /ssf/poll, authenticating\n" +
			"  as this client (HTTP Basic or mutual-TLS), and acknowledges each one\n" +
			"  so it can be dropped from the queue.")
		return nil
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
		SELECT s.client_id, s.delivery_method, COALESCE(s.endpoint_url, ''),
		       s.status, (s.auth_token IS NOT NULL), cardinality(s.events_requested)
		FROM core.ssf_streams s ORDER BY s.client_id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	n := 0
	fmt.Printf("\n  %-24s %-6s %-40s %-10s %s\n", "CLIENT", "MODE", "ENDPOINT", "STATUS", "AUTH")
	for rows.Next() {
		var client, method, endpoint, status string
		var hasToken bool
		var events int
		if err := rows.Scan(&client, &method, &endpoint, &status, &hasToken, &events); err != nil {
			return err
		}
		n++
		auth := "none"
		if hasToken {
			auth = "bearer"
		}
		if method == "poll" {
			// A poll stream has no endpoint, and the receiver authenticates as its
			// client when it pulls, so "auth" here would only ever be a token that
			// does not apply.
			endpoint, auth = "(pulled from /ssf/poll)", "client"
		}
		fmt.Printf("  %-24s %-6s %-40s %-10s %s (%d event types)\n",
			truncate(client, 24), method, truncate(endpoint, 40), status, auth, events)
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
	sanURI, sanIP, sanEmail, certPath string, boundTokens bool) error {

	if clientID == "" {
		return fmt.Errorf("give -client-id")
	}
	set := 0
	for _, v := range []string{subjectDN, sanDNS, sanURI, sanIP, sanEmail, certPath} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return fmt.Errorf("give exactly one of -tls-subject-dn, -tls-san-dns, " +
			"-tls-san-uri, -tls-san-ip, -tls-san-email (PKI) or -sp-cert (self-signed)")
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
		    tls_san_uri = NULLIF($4,''), tls_san_ip = NULLIF($5,''),
		    tls_san_email = NULLIF($6,''), tls_thumbprint = $7,
		    tls_bound_tokens = $8, updated_at = now()
		WHERE client_id = $1`,
		clientID, subjectDN, sanDNS, sanURI, sanIP, sanEmail, thumb, boundTokens)
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

	// Chrome Enterprise device trust, when a service account is configured.
	//
	// Constructed HERE rather than left as a package nothing builds. A posture
	// source that exists in the tree and is never instantiated is a feature that
	// passes its tests and does nothing in a running deployment -- which is
	// exactly how `internal/radius` came to be complete and unreachable.
	if credsPath := os.Getenv("SIGNARI_CHROME_CREDENTIALS"); credsPath != "" {
		raw, err := os.ReadFile(credsPath)
		if err != nil {
			return nil, fmt.Errorf("reading SIGNARI_CHROME_CREDENTIALS: %w", err)
		}
		creds, err := directory.ParseGoogleCredentials(raw)
		if err != nil {
			return nil, fmt.Errorf("SIGNARI_CHROME_CREDENTIALS: %w", err)
		}
		customer := os.Getenv("SIGNARI_CHROME_CUSTOMER_ID")
		if customer == "" {
			// Without it, a device managed by ANY Google Workspace customer is
			// accepted as managed, which is not a security property. Refused
			// rather than defaulted.
			return nil, fmt.Errorf("SIGNARI_CHROME_CUSTOMER_ID is required with " +
				"Chrome device trust: without it a device managed by any Workspace " +
				"customer counts as managed, which means nothing")
		}
		impersonate := os.Getenv("SIGNARI_CHROME_IMPERSONATE")
		cfg.Chrome = &posture.Chrome{
			CustomerID: customer,
			// Off unless asked for. Google reports `osFirewall` and we decode it,
			// but requiring it by default would refuse every managed fleet that
			// deliberately runs without a host firewall behind a network its own
			// administrators control -- a lockout imposed by this server to enforce
			// a policy nobody set here.
			RequireOSFirewall: os.Getenv("SIGNARI_CHROME_REQUIRE_FIREWALL") == "1",
			Token: func(ctx context.Context) (string, error) {
				return directory.GoogleToken(ctx, creds, impersonate,
					"https://www.googleapis.com/auth/verifiedaccess", nil)
			},
		}
		cfg.ChromeHeader = envOr("SIGNARI_CHROME_HEADER", "X-Verified-Access-Challenge-Response")
	}

	if cfg.DeviceCAs == nil && len(cfg.TrustedProxies) == 0 && cfg.Chrome == nil {
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

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

// inviteCreate mints one invitation and prints the link ONCE.
func inviteCreate(ctx context.Context, conn *pgx.Conn, orgID, email, groups string,
	ttl time.Duration, issuer string) error {

	if orgID == "" {
		return fmt.Errorf("give -org, the organisation the new account joins")
	}
	if ttl <= 0 || ttl > 90*24*time.Hour {
		return fmt.Errorf("-expires must be between a moment and 90 days; an "+
			"invitation that outlives the reason it was sent is a standing way in "+
			"(got %s)", ttl)
	}
	wanted := splitList(groups)
	// Checked now rather than at signup. A group named here that does not exist
	// produces an account with fewer permissions than intended, and nobody finds
	// out until the person cannot reach something.
	for _, g := range wanted {
		var exists bool
		if err := conn.QueryRow(ctx,
			`SELECT true FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
			orgID, g).Scan(&exists); err != nil {
			return fmt.Errorf("no group named %q in that organisation. Create it "+
				"first with `signari group create`, or the invitation would produce "+
				"an account without it and nobody would notice", g)
		}
	}

	token, hash, err := store.NewInvitationToken()
	if err != nil {
		return err
	}
	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.invitations
			(org_id, token_hash, email, grant_groups, expires_at)
		VALUES ($1::uuid, $2, NULLIF($3,''), $4, now() + $5::interval)
		RETURNING id::text`,
		orgID, hash, strings.ToLower(strings.TrimSpace(email)), wanted,
		fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&id); err != nil {
		return err
	}

	base := issuer
	if base == "" {
		base = os.Getenv("SIGNARI_ISSUER")
	}
	if base == "" {
		base = "https://<your issuer>"
	}
	fmt.Printf("invitation %s\n", id)
	fmt.Printf("  %s/signup?invite=%s\n", strings.TrimRight(base, "/"), token)
	if email != "" {
		fmt.Printf("  only %s may accept it\n", email)
	} else {
		fmt.Println("  anyone holding the link may accept it -- pass -email-invite to bind it")
	}
	if len(wanted) > 0 {
		fmt.Printf("  joins: %s\n", strings.Join(wanted, ", "))
	}
	fmt.Printf("  expires in %s\n", ttl)
	fmt.Println("\nThe link is shown once. It is stored hashed, so it cannot be printed again.")
	return nil
}

func inviteList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	rows, err := conn.Query(ctx, `
		SELECT id::text, COALESCE(email,''), grant_groups, expires_at,
		       used_at IS NOT NULL, revoked_at IS NOT NULL, expires_at < now()
		  FROM core.invitations WHERE org_id = $1::uuid
		 ORDER BY created_at DESC LIMIT 50`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, email string
		var groups []string
		var expires time.Time
		var used, revoked, expired bool
		if err := rows.Scan(&id, &email, &groups, &expires, &used, &revoked, &expired); err != nil {
			return err
		}
		state := "open"
		switch {
		case used:
			state = "used"
		case revoked:
			state = "revoked"
		case expired:
			state = "expired"
		}
		who := email
		if who == "" {
			who = "(anyone with the link)"
		}
		fmt.Printf("  %-8s %-34s %s\n", state, who, strings.Join(groups, ","))
		n++
	}
	if n == 0 {
		fmt.Println("  no invitations")
	}
	return rows.Err()
}

// signupEnable turns on open self-signup for an organisation.
func signupEnable(ctx context.Context, conn *pgx.Conn, orgID, domains, groups string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	d := splitList(domains)
	if len(d) == 0 {
		return fmt.Errorf("give -domains. Open signup with no domain restriction " +
			"lets anyone on the internet create an account in this organisation, and " +
			"that is not something to enable by leaving a flag off. Pass " +
			"-domains '*' if it is genuinely what you want")
	}
	if len(d) == 1 && d[0] == "*" {
		d = []string{}
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.signup_rules (org_id, allowed_domains, default_groups)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (org_id) DO UPDATE SET
			allowed_domains = EXCLUDED.allowed_domains,
			default_groups = EXCLUDED.default_groups,
			updated_at = now()`, orgID, d, splitList(groups)); err != nil {
		return err
	}
	if len(d) == 0 {
		fmt.Println("self-signup enabled for ANY email address")
	} else {
		fmt.Printf("self-signup enabled for: %s\n", strings.Join(d, ", "))
	}
	if g := splitList(groups); len(g) > 0 {
		fmt.Printf("  new accounts join: %s\n", strings.Join(g, ", "))
	}
	return nil
}

func signupDisable(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	tag, err := conn.Exec(ctx, `DELETE FROM core.signup_rules WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		fmt.Println("self-signup was already off")
		return nil
	}
	fmt.Println("self-signup disabled; only invitations create accounts now")
	return nil
}

func signupShow(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	var domains, groups []string
	var verify bool
	err := conn.QueryRow(ctx, `
		SELECT allowed_domains, default_groups, require_verified_email
		  FROM core.signup_rules WHERE org_id = $1::uuid`, orgID).
		Scan(&domains, &groups, &verify)
	if err != nil {
		fmt.Println("self-signup is off; accounts are created by invitation or by an administrator")
		return nil
	}
	if len(domains) == 0 {
		fmt.Println("self-signup: ANY email address")
	} else {
		fmt.Printf("self-signup: %s\n", strings.Join(domains, ", "))
	}
	if len(groups) > 0 {
		fmt.Printf("  new accounts join: %s\n", strings.Join(groups, ", "))
	}
	return nil
}

// outpostCreate issues a token for a remote protocol server.
func outpostCreate(ctx context.Context, conn *pgx.Conn, orgID, name, kind string) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org")
	case name == "":
		return fmt.Errorf("give -name, something that identifies where this outpost runs")
	}
	switch kind {
	case "ldap", "radius", "proxy", "desktop", "pdp":
	default:
		return fmt.Errorf("give -kind-outpost: ldap, radius, proxy, desktop or pdp. The token is "+
			"bound to one protocol, so a leaked token costs that protocol rather "+
			"than all of them (got %q)", kind)
	}

	token, hash, err := store.NewInvitationToken() // same 32-byte shape
	if err != nil {
		return err
	}
	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash)
		VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
		orgID, name, kind, hash).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("an outpost called %q already exists in that organisation", name)
		}
		return err
	}

	fmt.Printf("outpost %s (%s)\n\n", name, kind)
	fmt.Printf("  SIGNARI_OUTPOST_TOKEN=%s\n\n", token)
	fmt.Println("Run it where the protocol is needed, with NO database credentials:")
	fmt.Printf("  signari outpost run -core https://<this engine> \\\n")
	fmt.Printf("    -outpost-token $SIGNARI_OUTPOST_TOKEN -kind-outpost %s \\\n", kind)
	if kind == "ldap" {
		fmt.Printf("    -addr :389 -ldap-base-dn dc=example,dc=com\n")
	} else {
		fmt.Printf("    -addr :1812\n")
	}
	fmt.Println("\nThe token is shown once. It is stored hashed.")
	fmt.Println("It verifies passwords and nothing else: it cannot change anything,")
	fmt.Println("mint a session, or be used for a different protocol.")
	return nil
}

func outpostList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	rows, err := conn.Query(ctx, `
		SELECT name, kind, enabled, last_seen_at, COALESCE(last_seen_ip,'')
		  FROM core.outposts WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name, kind, ip string
		var enabled bool
		var seen *time.Time
		if err := rows.Scan(&name, &kind, &enabled, &seen, &ip); err != nil {
			return err
		}
		state := "enabled"
		if !enabled {
			state = "DISABLED"
		}
		last := "never called"
		if seen != nil {
			last = fmt.Sprintf("last seen %s ago from %s",
				time.Since(*seen).Round(time.Second), ip)
		}
		fmt.Printf("  %-20s %-7s %-9s %s\n", name, kind, state, last)
		n++
	}
	if n == 0 {
		fmt.Println("  no outposts registered")
	}
	return rows.Err()
}

// outpostRun serves a protocol against a remote core.
//
// No database handle exists in this process. That is the entire point: the
// machine running this can sit in a DMZ, a branch office or an airgapped
// segment, and a compromise of it does not yield the directory.
func outpostRun(core, token, kind, addr, baseDN string) error {
	if kind == "" {
		return fmt.Errorf("give -kind-outpost: ldap or radius")
	}
	if token == "" {
		token = os.Getenv("SIGNARI_OUTPOST_TOKEN")
	}
	client, err := outpost.New(core, token, 10*time.Second)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Checked BEFORE a listener opens. An outpost that starts anyway and finds
	// out its token is wrong when the first person tries to log in has turned a
	// configuration error into an outage, and the one who discovers it is a user.
	if err := client.Check(ctx); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	log.Info("outpost registered with the core", "name", client.Name(), "kind", kind,
		"core", core)

	switch kind {
	case "ldap":
		if baseDN == "" {
			return fmt.Errorf("give -ldap-base-dn: every bind DN sits under it and " +
				"there is no safe default")
		}
		if addr == ":8080" {
			addr = ":389"
		}
		srv := ldapd.New(ldapd.Config{
			BaseDN:      baseDN,
			UserAttr:    envOr("SIGNARI_LDAP_USER_ATTR", "uid"),
			MaxResults:  500,
			ReadTimeout: 30 * time.Second,
		}, client, log)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		log.Info("LDAP outpost listening", "addr", addr, "base_dn", baseDN)
		return srv.Serve(ctx, ln)
	case "radius":
		return fmt.Errorf("the RADIUS outpost needs its shared secrets, which are " +
			"per network device and are not carried by the outpost token. Configure " +
			"them locally and this will start; see docs/outposts.md")
	default:
		return fmt.Errorf("-kind-outpost %q cannot be run yet", kind)
	}
}

// clientSetHybrid permits response_type "code id_token" for one client.
func clientSetHybrid(ctx context.Context, conn *pgx.Conn, clientID, reviewBy string) error {
	if clientID == "" {
		return fmt.Errorf("give -client-id")
	}
	if reviewBy == "" {
		return fmt.Errorf("give -review-by, a date when this should be revisited. " +
			"Hybrid exists here for applications being migrated in; an exemption " +
			"with no date on it is a permanent one that nobody decided to make")
	}
	if _, err := time.Parse("2006-01-02", reviewBy); err != nil {
		return fmt.Errorf("-review-by must be YYYY-MM-DD (got %q)", reviewBy)
	}
	// response_types is updated alongside the flag rather than left to disagree
	// with it. Two switches for one decision means an operator turns on the one
	// they found and gets refused by the one they did not.
	tag, err := conn.Exec(ctx, `
		UPDATE core.clients
		   SET allow_hybrid = true,
		       hybrid_review_by = $2::date,
		       response_types = (
		           SELECT array_agg(DISTINCT rt)
		             FROM unnest(response_types || ARRAY['code id_token']) AS rt)
		 WHERE client_id = $1`, clientID, reviewBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}
	fmt.Printf("%s may now use response_type \"code id_token\"\n", clientID)
	fmt.Printf("  review by %s\n", reviewBy)
	fmt.Println("  the access token still never crosses the front channel")
	return nil
}

// logoutTest checks a relying party's back-channel logout endpoint.
func logoutTest(ctx context.Context, conn *pgx.Conn, rpURL, clientID, issuer,
	subject, sid string) error {

	if issuer == "" {
		issuer = os.Getenv("SIGNARI_ISSUER")
	}
	if issuer == "" {
		return fmt.Errorf("give -issuer, so the tokens carry the issuer the relying " +
			"party expects")
	}

	_, set, _, err := loadInstanceKeys(ctx, conn)
	if err != nil {
		return err
	}
	// RS256 first: a logout endpoint is exactly the kind of lightly-maintained
	// code path most likely to support only RS256, and testing with a key it
	// cannot verify would report a failure that is ours.
	key, err := set.Active(keys.RS256)
	if err != nil {
		if key, err = set.Active(keys.ES256); err != nil {
			return fmt.Errorf("no active signing key: %w", err)
		}
	}

	results, err := logouttest.Run(ctx, logouttest.Config{
		Endpoint: rpURL, ClientID: clientID, Issuer: issuer,
		Subject: subject, SID: sid,
	}, key)
	if err != nil {
		return err
	}

	fmt.Printf("back-channel logout: %s\n\n", rpURL)
	passed, failed := 0, 0
	for _, r := range results {
		mark := "ok  "
		switch {
		case r.Err != "":
			mark = "??  "
		case r.Passed:
			passed++
		default:
			mark = "FAIL"
			failed++
		}
		detail := fmt.Sprintf("HTTP %d", r.Status)
		if r.Err != "" {
			detail = r.Err
		}
		fmt.Printf("  [%s] %-34s %s\n", mark, r.Name, detail)
		if mark == "FAIL" {
			want := "refuse it"
			if r.WantAccepted {
				want = "accept it"
			}
			fmt.Printf("         expected the endpoint to %s. %s\n", want, r.Why)
		}
	}

	fmt.Printf("\n  %d passed, %d failed\n", passed, failed)
	fmt.Println("\nThis proves the endpoint accepted or refused each token.")
	fmt.Println("It CANNOT prove the session was actually destroyed -- a relying party")
	fmt.Println("that validates correctly and then forgets to delete the session still")
	fmt.Println("passes every check here.")
	if failed > 0 {
		return fmt.Errorf("%d conformance check(s) failed", failed)
	}
	return nil
}

// idpAppleSecret mints Apple's client secret and stores it.
//
// Apple is the only provider whose client secret is a JWT this side signs, and
// it expires within six months. Running this again before then is the whole
// maintenance story; the alternative everyone else lives with is a calendar
// reminder that outlives whoever set it.
func idpAppleSecret(ctx context.Context, conn *pgx.Conn, slug, team, keyID, keyFile string) error {
	if slug == "" {
		return fmt.Errorf("give -slug, the provider to update")
	}
	var clientID, kind string
	if err := conn.QueryRow(ctx,
		`SELECT client_id, kind FROM core.identity_providers WHERE slug = $1`,
		slug).Scan(&clientID, &kind); err != nil {
		return fmt.Errorf("no identity provider with slug %q", slug)
	}
	if kind != string(federation.KindApple) {
		return fmt.Errorf("%q is a %s provider; only Apple uses a signed client secret",
			slug, kind)
	}
	if keyFile == "" {
		return fmt.Errorf("give -apple-key, the path to the .p8 file downloaded from " +
			"the developer portal")
	}
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("reading the .p8 key: %w", err)
	}

	secret, expiry, err := federation.MintAppleSecret(federation.AppleSecretInput{
		TeamID:        team,
		ClientID:      clientID,
		KeyID:         keyID,
		PrivateKeyPEM: string(pemBytes),
	}, time.Now())
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx,
		`UPDATE core.identity_providers SET client_secret = $2, updated_at = now()
		  WHERE slug = $1`, slug, secret); err != nil {
		return err
	}

	fmt.Printf("minted Apple client secret for %s\n", slug)
	fmt.Printf("  services id : %s\n", clientID)
	fmt.Printf("  expires     : %s (in %d days)\n",
		expiry.Format("2006-01-02"), int(time.Until(expiry).Hours()/24))
	fmt.Println("\nApple caps this at six months. Run this again before it expires;")
	fmt.Println("an expired secret fails as invalid_client, which reads like the")
	fmt.Println("credentials are wrong rather than out of date.")
	return nil
}

// kindNamesForHelp keeps the flag's help text in step with the presets.
func kindNamesForHelp() []string {
	ks := federation.Kinds()
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, string(k))
	}
	return out
}

// provisionAdd registers a Google Workspace or Entra provisioning target.
//
// These are the connectors the comparable product charges for. The
// reconciliation above them is the same one SCIM targets use, which is why
// adding them was a day rather than a quarter.
func provisionAdd(ctx context.Context, conn *pgx.Conn, orgID, slug, name, kind,
	credsFile, impersonate, domain, onDeactivate string, dryRun bool) error {

	switch {
	case orgID == "":
		return fmt.Errorf("give -org")
	case slug == "":
		return fmt.Errorf("give -slug")
	case credsFile == "":
		return fmt.Errorf("give -credentials, the service account JSON (Google) or " +
			"client credentials (Entra)")
	}
	switch kind {
	case "google":
		if impersonate == "" {
			return fmt.Errorf("give -impersonate: a Google service account with " +
				"domain-wide delegation does nothing without an administrator to act as")
		}
		if domain == "" {
			return fmt.Errorf("give -target-domain, so new accounts are created " +
				"somewhere rather than nowhere")
		}
	case "entra":
	default:
		return fmt.Errorf("give -kind-outpost google or entra (got %q). For a SCIM "+
			"server use `signari scim add`", kind)
	}

	raw, err := os.ReadFile(credsFile)
	if err != nil {
		return fmt.Errorf("reading the credentials: %w", err)
	}
	// Parsed now rather than at first sync, so a wrong file is a message here
	// instead of a cron job failing quietly at 3am.
	switch kind {
	case "google":
		if _, perr := directory.ParseGoogleCredentials(raw); perr != nil {
			return perr
		}
	case "entra":
		if _, perr := directory.ParseEntraCredentials(raw); perr != nil {
			return perr
		}
	}

	root, err := rootKey()
	if err != nil {
		return err
	}
	sealed, err := root.Seal(raw, "provision_credentials")
	if err != nil {
		return err
	}
	if onDeactivate == "" {
		onDeactivate = "deactivate"
	}
	if name == "" {
		name = slug
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.scim_targets
			(org_id, slug, display_name, kind, credentials_enc, impersonate,
			 target_domain, base_url, token, on_deactivate, dry_run)
		VALUES ($1::uuid, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), '', '', $8, $9)`,
		orgID, slug, name, kind, sealed, impersonate, domain,
		onDeactivate, dryRun); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("a target called %q already exists", slug)
		}
		return err
	}

	fmt.Printf("provisioning target %s (%s)\n", slug, kind)
	if impersonate != "" {
		fmt.Printf("  acting as   %s\n", impersonate)
	}
	if domain != "" {
		fmt.Printf("  domain      %s\n", domain)
	}
	fmt.Printf("  on leave    %s\n", onDeactivate)
	fmt.Println("\nRun `signari scim sync` to see what it would change.")
	fmt.Println("It is a DRY RUN until you pass -apply.")
	return nil
}

// kerberosCheck proves a keytab before a user meets it.
//
// Kerberos fails in ways the error never explains. A wrong service principal, a
// keytab exported at the wrong key version, a clock forty seconds out, an
// encryption type the KDC has disabled -- every one of them reaches the user as
// the browser quietly falling back to a password prompt, and reaches the
// operator as nothing at all.
//
// This is worth more than the authentication it checks.
func kerberosCheck(keytabPath, realm, spn string) error {
	if keytabPath == "" {
		return fmt.Errorf("give -keytab, the service keytab exported from the KDC")
	}
	cfg := kerberos.Config{KeytabPath: keytabPath, Realm: realm, ServicePrincipal: spn}

	kt, err := cfg.Keytab()
	if err != nil {
		return err
	}
	entries := kerberos.Entries(kt)

	fmt.Printf("keytab %s\n", keytabPath)
	fmt.Printf("  %d principal(s)\n\n", len(entries))

	problems := 0
	sawSPN := spn == ""
	strong := false
	for _, e := range entries {
		mark := " "
		if kerberos.Weak(e.EncType) {
			mark = "!"
			problems++
		} else {
			strong = true
		}
		fmt.Printf("  %s %-44s kvno %-4d %s\n", mark, e.Principal, e.KVNO,
			kerberos.EncTypeName(e.EncType))
		if spn != "" && strings.HasPrefix(strings.ToLower(e.Principal),
			strings.ToLower(spn)) {
			sawSPN = true
		}
	}

	fmt.Println()
	if !sawSPN {
		fmt.Printf("  PROBLEM: no entry for %s.\n", spn)
		fmt.Println("    The browser asks the KDC for a ticket to THIS name. A keytab")
		fmt.Println("    without it authenticates nobody, and the browser falls back to")
		fmt.Println("    a password prompt without saying why.")
		problems++
	}
	if !strong {
		fmt.Println("  PROBLEM: every entry uses an encryption type current KDCs disable.")
		fmt.Println("    Re-export with AES: ktpass ... /crypto AES256-SHA1, or")
		fmt.Println("    ipa-getkeytab without -e rc4-hmac.")
		problems++
	}
	if realm != "" && realm != strings.ToUpper(realm) {
		fmt.Printf("  NOTE: realms are upper case by convention; %q is unusual and\n", realm)
		fmt.Println("    a mismatched case is a common cause of tickets being refused.")
	}

	// The clock. Kerberos refuses a ticket more than five minutes out, and the
	// symptom is indistinguishable from a wrong password.
	fmt.Println()
	fmt.Println("  Clock skew is the other common cause and cannot be checked from here:")
	fmt.Println("    compare `date -u` on this host against the KDC. More than five")
	fmt.Println("    minutes apart and every ticket is refused as though the credentials")
	fmt.Println("    were wrong.")

	if problems > 0 {
		return fmt.Errorf("%d problem(s) would stop SPNEGO working", problems)
	}
	fmt.Println("\n  This keytab looks usable.")
	return nil
}

// configPlan diffs a configuration file against the deployment, and optionally
// applies it.
//
// Plan and apply share this function because they must share the diff. Two code
// paths mean the plan can describe something the apply does not do, which is
// the one failure a plan exists to prevent.
func configPlan(ctx context.Context, conn *pgx.Conn, orgID, path string,
	prune, doApply bool) error {

	if path == "" {
		return fmt.Errorf("give -f, the configuration file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := config.Parse(raw)
	if err != nil {
		return err
	}
	if orgID == "" {
		orgID = f.Org
	}
	if orgID == "" {
		return fmt.Errorf("give -org, or set `org:` in the file")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	plan, err := config.BuildPlan(ctx, tx, orgID, f, prune)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n\n%s", path, plan.String())
	create, update, del := plan.Counts()
	fmt.Printf("\n  %d to create, %d to update, %d to delete\n", create, update, del)

	if d := plan.Destructive(); len(d) > 0 {
		fmt.Println("\n  These REMOVE things:")
		for _, c := range d {
			fmt.Printf("    - %s %s — %s\n", c.Kind, c.Name, c.Detail)
		}
	}

	if !doApply {
		if plan.Empty() {
			return nil
		}
		fmt.Println("\nNothing was changed. Run `signari apply` to make it so.")
		if !prune {
			fmt.Println("Anything not in the file was left alone; -prune would delete it.")
		}
		return nil
	}

	if plan.Empty() {
		return nil
	}
	if err := config.Apply(ctx, tx, orgID, f, plan); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("\napplied")
	return nil
}

// promptDef is the YAML shape of a sign-in prompt.
type promptDef struct {
	Slug   string          `yaml:"slug"`
	Title  string          `yaml:"title"`
	Body   string          `yaml:"body"`
	Once   *bool           `yaml:"once"`
	Order  int             `yaml:"order"`
	Fields []prompts.Field `yaml:"fields"`
}

// promptSet defines or replaces a prompt shown during sign-in.
func promptSet(ctx context.Context, conn *pgx.Conn, orgID, slug, path string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	if path == "" {
		return fmt.Errorf("give -prompt-file, the YAML defining the prompt")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var d promptDef
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("the prompt did not parse: %w", err)
	}
	if slug != "" {
		d.Slug = slug
	}

	p := prompts.Prompt{Slug: d.Slug, Title: d.Title, Body: d.Body, Fields: d.Fields}
	// Validated before it is stored. A prompt that cannot be answered is shown
	// on every sign-in forever, and the person who notices is every user.
	if err := p.Validate(); err != nil {
		return err
	}
	once := true
	if d.Once != nil {
		once = *d.Once
	}

	fields, err := json.Marshal(d.Fields)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, body, fields, once, position)
		VALUES ($1::uuid, $2, $3, NULLIF($4,''), $5, $6, $7)
		ON CONFLICT (org_id, slug) DO UPDATE SET
			title = EXCLUDED.title, body = EXCLUDED.body, fields = EXCLUDED.fields,
			once = EXCLUDED.once, position = EXCLUDED.position, updated_at = now()`,
		orgID, d.Slug, d.Title, d.Body, fields, once, d.Order); err != nil {
		return err
	}

	fmt.Printf("prompt %s\n", d.Slug)
	fmt.Printf("  %s\n", d.Title)
	for _, f := range d.Fields {
		req := ""
		if f.Required {
			req = " (required)"
		}
		fmt.Printf("    %-10s %s%s\n", f.Type, f.Label, req)
	}
	if once {
		fmt.Println("  asked until answered, then never again")
	} else {
		fmt.Println("  asked on EVERY sign-in")
	}
	fmt.Println("\nIt is shown between authentication and the session, on every")
	fmt.Println("sign-in route -- password, passkey, MFA, Kerberos and federated.")
	return nil
}

func promptList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	rows, err := conn.Query(ctx, `
		SELECT p.slug, p.title, p.once, p.enabled,
		       (SELECT count(*) FROM core.prompt_responses r WHERE r.prompt_id = p.id)
		  FROM core.prompts p WHERE p.org_id = $1::uuid
		 ORDER BY p.position, p.slug`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var slug, title string
		var once, enabled bool
		var answered int
		if err := rows.Scan(&slug, &title, &once, &enabled, &answered); err != nil {
			return err
		}
		state := "enabled"
		if !enabled {
			state = "disabled"
		}
		mode := "once"
		if !once {
			mode = "every sign-in"
		}
		fmt.Printf("  %-18s %-30s %-9s %-14s %d answered\n",
			slug, title, state, mode, answered)
		n++
	}
	if n == 0 {
		fmt.Println("  no prompts")
	}
	return rows.Err()
}

// kerberosPrincipals lists what the realm holds, without changing anything.
func kerberosPrincipals(ctx context.Context, realm, adminPrincipal, keytabPath string) error {
	a := kerberos.Admin{Realm: realm, Principal: adminPrincipal, KeytabPath: keytabPath}
	names, err := a.Principals(ctx)
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Printf("  %s@%s\n", n, strings.ToUpper(realm))
	}
	fmt.Printf("\n  %d principal(s), service and administrative ones excluded\n", len(names))
	return nil
}

// kerberosSync creates accounts for the people in a realm.
//
// A dry run unless -apply, like every other sync here. It never deletes: a
// principal that has gone from the realm is a leaver, and what happens to a
// leaver's account is a policy decision rather than something a listing decides.
func kerberosSync(ctx context.Context, conn *pgx.Conn, orgID, realm,
	adminPrincipal, keytabPath string, apply bool) error {

	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	a := kerberos.Admin{Realm: realm, Principal: adminPrincipal, KeytabPath: keytabPath}
	names, err := a.Principals(ctx)
	if err != nil {
		return err
	}

	cfg := kerberos.Config{Realm: realm}
	created, existing := 0, 0
	for _, n := range names {
		email, merr := cfg.UsernameFor(n + "@" + strings.ToUpper(realm))
		if merr != nil {
			fmt.Printf("  skipped %s: %v\n", n, merr)
			continue
		}
		var found bool
		if err := conn.QueryRow(ctx, `
			SELECT true FROM core.users WHERE org_id = $1::uuid AND lower(email) = lower($2)`,
			orgID, email).Scan(&found); err == nil && found {
			existing++
			continue
		}
		created++
		if !apply {
			fmt.Printf("  would create %s\n", email)
			continue
		}
		// No password credential. The account authenticates against the realm --
		// by SPNEGO or by the password backend -- and inventing a local password
		// for it would be a second way in that nobody chose.
		if _, err := conn.Exec(ctx, `
			INSERT INTO core.users (org_id, user_handle, email)
			VALUES ($1::uuid, decode(repeat(md5(random()::text),4),'hex'), $2)
			ON CONFLICT DO NOTHING`, orgID, email); err != nil {
			return fmt.Errorf("creating %s: %w", email, err)
		}
		fmt.Printf("  created %s\n", email)
	}

	fmt.Printf("\n  %d already here, %d to create\n", existing, created)
	if !apply && created > 0 {
		fmt.Println("\nNothing was changed. Re-run with -apply.")
	}
	fmt.Println("\nAccounts are created without a local password: they authenticate")
	fmt.Println("against the realm. Nothing is ever deleted here -- what happens to a")
	fmt.Println("leaver is a policy decision, not something a listing should make.")
	return nil
}

// eventsSubscribe registers a subscriber and prints its signing secret once.
func eventsSubscribe(ctx context.Context, conn *pgx.Conn,
	orgID, name, url, events string) error {

	if orgID == "" || name == "" || url == "" {
		return fmt.Errorf("-org, -name and -url are all required")
	}
	root, err := rootKey()
	if err != nil {
		return fmt.Errorf("the signing secret is sealed with the root key: %w", err)
	}
	var types []string
	for _, t := range strings.Split(events, ",") {
		if t = strings.TrimSpace(t); t != "" {
			types = append(types, t)
		}
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	sub, err := store.CreateSubscription(ctx, tx, root, orgID, name, url, types)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("subscription %s\n  url    %s\n", sub.ID, sub.URL)
	if len(types) == 0 {
		fmt.Printf("  events every event in this organisation\n")
	} else {
		fmt.Printf("  events %s\n", strings.Join(types, ", "))
	}
	// Shown ONCE. Stored sealed and never printed again, so a database copy is
	// not a licence to forge events -- an operator who loses it rotates.
	fmt.Printf("\n  signing secret (shown once, store it now):\n    %s\n", sub.Secret)
	fmt.Printf(`
  Verify each delivery:  the Signari-Signature header is t=<unix>,v1=<hex>,
  and v1 is HMAC-SHA256 over "<t>.<raw request body>" with that secret.
  Refuse anything whose t is more than a few minutes old -- the timestamp is
  inside the MAC precisely so that check cannot be bypassed.
`)
	return nil
}

// eventsList shows subscriptions and how their deliveries are going.
func eventsList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	rows, err := conn.Query(ctx, `
		SELECT s.display_name, s.url, s.enabled, COALESCE(s.disabled_reason,''),
		       COALESCE(cardinality(s.event_types),0),
		       (SELECT count(*) FROM core.event_deliveries d
		         WHERE d.subscription_id = s.id AND d.delivered_at IS NOT NULL),
		       (SELECT count(*) FROM core.event_deliveries d
		         WHERE d.subscription_id = s.id AND d.delivered_at IS NULL)
		  FROM core.event_subscriptions s
		 WHERE s.org_id = $1::uuid
		 ORDER BY s.created_at`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var name, url, why string
		var enabled bool
		var types, delivered, outstanding int
		if err := rows.Scan(&name, &url, &enabled, &why, &types, &delivered,
			&outstanding); err != nil {
			return err
		}
		found = true
		state := "enabled"
		if !enabled {
			state = "DISABLED"
		}
		scope := "all events"
		if types > 0 {
			scope = fmt.Sprintf("%d event type(s)", types)
		}
		fmt.Printf("%-24s %s\n  %s, %s\n  delivered %d, outstanding %d\n",
			name, url, state, scope, delivered, outstanding)
		if why != "" {
			fmt.Printf("  reason: %s\n", why)
		}
	}
	if !found {
		fmt.Println("no event subscriptions")
	}
	return rows.Err()
}

// authzModelSet parses a model, runs its own tests, and stores it.
func authzModelSet(ctx context.Context, conn *pgx.Conn, orgID, file string) error {
	if orgID == "" || file == "" {
		return fmt.Errorf("-org and -file are both required")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	// Parse RUNS the model's tests. A model whose own examples fail does not
	// load, so it cannot be stored and discovered wrong in production.
	m, err := authzen.ParseModel(data)
	if err != nil {
		return err
	}
	if err := store.SaveModel(ctx, conn, orgID, string(data), m, ""); err != nil {
		return err
	}
	types := 0
	actions := 0
	for _, t := range m.Types {
		types++
		actions += len(t.Permissions)
	}
	fmt.Printf("model stored: %d type(s), %d action(s), %d test(s) passed\n",
		types, actions, len(m.Tests))
	return nil
}

// authzModelShow prints the model as written.
func authzModelShow(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	src, err := store.ModelSource(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if src == "" {
		fmt.Println("no authorization model; nothing is permitted")
		return nil
	}
	fmt.Print(src)
	return nil
}

// splitRef parses type:id and says which part is wrong when it will not.
func splitRef(flag, ref string) (typ, id string, err error) {
	typ, id, ok := authzen.ParseRef(ref)
	if !ok {
		return "", "", fmt.Errorf("%s must be type:id (got %q)", flag, ref)
	}
	return typ, id, nil
}

func authzGrant(ctx context.Context, conn *pgx.Conn, orgID, subject, relation, object string) error {
	if orgID == "" || subject == "" || relation == "" || object == "" {
		return fmt.Errorf("-org, -principal, -relation and -object are all required")
	}
	styp, sid, err := splitRef("-principal", subject)
	if err != nil {
		return err
	}
	otyp, oid, err := splitRef("-object", object)
	if err != nil {
		return err
	}
	if err := store.GrantRelation(ctx, conn, orgID, store.Relation{
		SubjectType: styp, SubjectID: sid, Relation: relation,
		ObjectType: otyp, ObjectID: oid,
	}, ""); err != nil {
		return err
	}
	fmt.Printf("%s is %s of %s\n", subject, relation, object)
	return nil
}

func authzRevoke(ctx context.Context, conn *pgx.Conn, orgID, subject, relation, object string) error {
	if orgID == "" || subject == "" || relation == "" || object == "" {
		return fmt.Errorf("-org, -principal, -relation and -object are all required")
	}
	styp, sid, err := splitRef("-principal", subject)
	if err != nil {
		return err
	}
	otyp, oid, err := splitRef("-object", object)
	if err != nil {
		return err
	}
	if err := store.RevokeRelation(ctx, conn, orgID, store.Relation{
		SubjectType: styp, SubjectID: sid, Relation: relation,
		ObjectType: otyp, ObjectID: oid,
	}); err != nil {
		return err
	}
	fmt.Printf("%s is no longer %s of %s\n", subject, relation, object)
	return nil
}

// authzCheck answers a question from the command line.
//
// The same question the API answers, so an operator debugging "why was this
// refused" gets the reason rather than having to reproduce the HTTP call.
func authzCheck(ctx context.Context, conn *pgx.Conn, orgID, subject, action, object string) error {
	if orgID == "" || subject == "" || action == "" || object == "" {
		return fmt.Errorf("-org, -principal, -action and -object are all required")
	}
	styp, sid, err := splitRef("-principal", subject)
	if err != nil {
		return err
	}
	otyp, oid, err := splitRef("-object", object)
	if err != nil {
		return err
	}
	m, err := store.LoadModel(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("this organisation has no authorization model, so nothing " +
			"is permitted -- set one with `signari authz model set`")
	}
	relations, defined := m.RelationsFor(otyp, action)
	if !defined {
		return fmt.Errorf("the model defines no action %q on %s", action, otyp)
	}

	var groups []string
	if userID, rerr := store.ResolveSubject(ctx, conn, orgID, sid); rerr == nil && userID != "" {
		if f, ferr := store.SubjectFacts(ctx, conn, orgID, userID, ""); ferr == nil {
			groups = f.Groups
		}
	}
	held, err := store.HoldsAny(ctx, conn, orgID, styp, sid, relations, otyp, oid, groups)
	if err != nil {
		return err
	}
	if held == "" {
		fmt.Printf("DENIED  %s may not %s %s\n  %s.%s is granted to: %s\n",
			subject, action, object, otyp, action, strings.Join(relations, ", "))
		if len(groups) > 0 {
			fmt.Printf("  groups considered: %s\n", strings.Join(groups, ", "))
		}
		return nil
	}
	fmt.Printf("ALLOWED %s may %s %s\n  via relation: %s\n", subject, action, object, held)
	if c, has := m.ConditionFor(otyp, action); has {
		fmt.Printf("  NOTE: at runtime this also requires %s, which is a property of "+
			"the session and cannot be checked from here\n", conditionSummary(c.Condition))
	}
	return nil
}

func conditionSummary(c authzen.Condition) string {
	var parts []string
	if c.MFA {
		parts = append(parts, "a second factor")
	}
	if c.DeviceManaged {
		parts = append(parts, "a managed device")
	}
	if c.DeviceCompliant {
		parts = append(parts, "a compliant device")
	}
	if c.MaxRisk > 0 {
		parts = append(parts, fmt.Sprintf("risk at most %d", c.MaxRisk))
	}
	if len(c.AnyGroup) > 0 {
		parts = append(parts, "membership of "+strings.Join(c.AnyGroup, " or "))
	}
	return strings.Join(parts, " and ")
}

// ssfAddSource registers a transmitter we will accept events from.
func ssfAddSource(ctx context.Context, conn *pgx.Conn, orgID, name, issuer,
	jwksURI, audience, events, criticalMembers string) error {

	switch {
	case orgID == "" || name == "":
		return fmt.Errorf("-org and -name are required")
	case issuer == "":
		return fmt.Errorf("-source-issuer is required: every event must carry " +
			"exactly this in `iss`, and it is what selects the keys to verify against")
	case jwksURI == "":
		return fmt.Errorf("-source-jwks is required: keys come from there, never " +
			"from the token")
	case !strings.HasPrefix(jwksURI, "https://"):
		return fmt.Errorf("-source-jwks must be https")
	case audience == "":
		return fmt.Errorf("-source-audience is required: a token addressed to " +
			"somebody else is not ours to act on, however valid its signature")
	}

	var list []string
	for _, e := range strings.Split(events, ",") {
		if e = strings.TrimSpace(e); e != "" {
			list = append(list, e)
		}
	}
	if len(list) == 0 {
		return fmt.Errorf("-events is required: a source permitted to send nothing "+
			"is not useful, and one permitted to send everything is not what you "+
			"meant. Try -events %s", ssf.EventSessionRevoked)
	}

	var critical []string
	for _, m := range strings.Split(criticalMembers, ",") {
		if m = strings.TrimSpace(m); m != "" {
			critical = append(critical, m)
		}
	}
	if err := store.AddSource(ctx, conn, orgID, name, issuer, jwksURI, audience,
		list, critical); err != nil {
		return err
	}
	fmt.Printf("source %s\n  issuer   %s\n  jwks     %s\n  audience %s\n  events   %s\n",
		name, issuer, jwksURI, audience, strings.Join(list, ", "))
	if len(critical) > 0 {
		// Worth printing, because it is the one setting here that makes this
		// receiver DISCARD events it would otherwise act on.
		fmt.Printf("  critical %s  (events carrying these are discarded unless understood)\n",
			strings.Join(critical, ", "))
	}
	fmt.Printf("\n  Point the transmitter at:  POST <this engine>/ssf/receive\n")
	fmt.Printf("  It needs no credential -- the signature is the credential.\n")
	return nil
}

// ssfReceived shows what sources have sent, and what was done about it.
func ssfReceived(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("-org is required")
	}
	rows, err := store.RecentReceived(ctx, conn, orgID, 50)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no events received")
		return nil
	}
	for _, r := range rows {
		short := r.EventType
		if i := strings.LastIndex(short, "/"); i >= 0 {
			short = short[i+1:]
		}
		fmt.Printf("%s  %-18s %-20s %s\n",
			r.ReceivedAt.Format("2006-01-02 15:04:05"), short, r.Action, r.Detail)
	}
	return nil
}

// federationEnable joins this instance to an OpenID Federation.
//
// Two things happen, and neither is reversible by accident: an Entity Statement
// signing key is generated, and a federation_config row is written. From then on
// /.well-known/openid-federation serves a signed statement about this entity.
//
// The key is generated here rather than reusing the protocol keys, because
// OpenID Federation 1.0 §3.1.1 says "These Federation Entity Keys SHOULD NOT be
// used in other protocols". Reusing them would tie two independent trust
// decisions together: a relying party trusting our OIDC key to say who a user
// is, and a federation trusting our federation key to say what this entity is.
func federationEnable(ctx context.Context, conn *pgx.Conn, hints, orgName, homepage string) error {
	root, err := rootKey()
	if err != nil {
		return err
	}
	instanceID, issuer, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	if err := oidfed.ValidateEntityID(issuer); err != nil {
		return fmt.Errorf("this instance cannot be a federation entity: %w", err)
	}

	// §3.1.2: authority_hints "MUST NOT be the empty array". Absent means "Trust
	// Anchor with no superiors", which is a real and different thing -- so an
	// empty flag is passed through as nil rather than as [].
	var hintList []string
	for _, h := range strings.Split(hints, ",") {
		if h = strings.TrimSpace(h); h != "" {
			if err := oidfed.ValidateEntityID(h); err != nil {
				return fmt.Errorf("authority hint %q: %w", h, err)
			}
			hintList = append(hintList, h)
		}
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// One key, ES256, active immediately. Rotation uses the same machinery as
	// the protocol keys because it is the same table.
	var existing int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM core.signing_keys
		WHERE instance_id = $1::uuid AND purpose = 'federation' AND state = 'active'`,
		instanceID).Scan(&existing); err != nil {
		return err
	}
	if existing == 0 {
		k, err := keys.Generate(keys.NewKID(), keys.ES256)
		if err != nil {
			return fmt.Errorf("generating the federation key: %w", err)
		}
		// Active immediately, not `next`.
		//
		// A protocol key is published as `next` first so relying parties can
		// fetch it before it signs anything -- that staging is what makes an OIDC
		// rotation safe. A federation entity has no such audience yet: the very
		// first Entity Configuration is signed by this key, and a `next` key
		// signs nothing, so staging it would publish an endpoint that answers 500.
		//
		// (It did, in the first version of this command. The key was saved in
		// whatever state Generate leaves, the endpoint asked for an ACTIVE one,
		// and the two never met.)
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			return err
		}
		if err := keys.SaveFor(ctx, tx, instanceID, keys.PurposeFederation, active, root); err != nil {
			return err
		}
		k = active
		fmt.Printf("generated federation key %s (ES256)\n", k.KID())
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.federation_config
			(instance_id, authority_hints, organization_name, homepage_uri)
		VALUES ($1::uuid, $2, NULLIF($3,''), NULLIF($4,''))
		ON CONFLICT (instance_id) DO UPDATE SET
			authority_hints   = EXCLUDED.authority_hints,
			organization_name = EXCLUDED.organization_name,
			homepage_uri      = EXCLUDED.homepage_uri,
			updated_at        = now()`,
		instanceID, hintList, orgName, homepage); err != nil {
		return fmt.Errorf("saving the federation configuration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	url, _ := oidfed.ConfigurationURL(issuer)
	fmt.Printf("federation enabled\n  entity id : %s\n  published : %s\n", issuer, url)
	if len(hintList) == 0 {
		fmt.Println("  no authority_hints: this entity is published as a Trust Anchor " +
			"with no superiors. If it has one, re-run with -authority-hints.")
	} else {
		fmt.Printf("  superiors : %s\n", strings.Join(hintList, ", "))
	}
	fmt.Println("  restart `signari serve` to register the endpoint")
	return nil
}

// federationShow prints what this instance publishes.
func federationShow(ctx context.Context, conn *pgx.Conn) error {
	instanceID, issuer, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	var hints []string
	var orgName, homepage *string
	var lifetime int
	if err := conn.QueryRow(ctx, `
		SELECT authority_hints, organization_name, homepage_uri, lifetime_seconds
		FROM core.federation_config WHERE instance_id = $1::uuid`, instanceID).
		Scan(&hints, &orgName, &homepage, &lifetime); err != nil {
		return fmt.Errorf("this instance is not part of a federation -- " +
			"run `signari federation enable`")
	}
	var nkeys int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM core.signing_keys
		WHERE instance_id = $1::uuid AND purpose = 'federation' AND state IN ('active','next')`,
		instanceID).Scan(&nkeys)

	url, _ := oidfed.ConfigurationURL(issuer)
	fmt.Printf("entity id       %s\n", issuer)
	fmt.Printf("published at    %s\n", url)
	fmt.Printf("federation keys %d\n", nkeys)
	fmt.Printf("lifetime        %ds\n", lifetime)
	if len(hints) == 0 {
		fmt.Println("authority_hints (none -- published as a Trust Anchor)")
	} else {
		fmt.Printf("authority_hints %s\n", strings.Join(hints, ", "))
	}
	return nil
}

// credentialOffer mints an OID4VCI Credential Offer.
//
// The operator's half of the pre-authorized code grant. §3.4 puts the offer in a
// QR code or a deep link; §6.1 lets the wallet redeem it at /oauth2/token
// sending nothing but the code, so everything that decides what the resulting
// token can do is decided HERE.
func credentialOffer(ctx context.Context, conn *pgx.Conn, orgID, email, clientID,
	configs, credIssuer, issuer string, wantTxCode bool, txLength int,
	ttl time.Duration) error {

	if orgID == "" {
		return fmt.Errorf("give -org, the organisation the holder belongs to")
	}
	if email == "" {
		return fmt.Errorf("give -email, the person this credential is about")
	}
	if clientID == "" {
		return fmt.Errorf("give -client-id, the wallet client whose scopes and " +
			"token lifetimes the redemption uses. OID4VCI section 6.1 lets the " +
			"wallet omit client_id when it redeems, so this is the only chance to " +
			"decide it")
	}
	ids := splitList(configs)
	if len(ids) == 0 {
		return fmt.Errorf("give -credential-configuration: at least one " +
			"credential_configuration_id, as it appears in the Credential Issuer's " +
			"metadata. An offer of nothing is not an offer")
	}
	if ttl <= 0 || ttl > time.Hour {
		return fmt.Errorf("-offer-expires must be between a moment and an hour; "+
			"section 3.5 says a pre-authorized code MUST be short lived, and it is "+
			"redeemed within seconds of being scanned (got %s)", ttl)
	}

	// The Credential Issuer identifier the wallet will fetch metadata from.
	//
	// Defaulted to this deployment's issuer, which is right only when Signari is
	// both the authorization server and the credential issuer. §12.2.3 makes the
	// two identifiers a mix-up defence, so a deployment where they differ has to
	// say so rather than have one silently stand in for the other.
	ci := credIssuer
	if ci == "" {
		ci = issuer
	}
	if ci == "" {
		ci = os.Getenv("SIGNARI_ISSUER")
	}
	if err := oid4vci.ValidateIssuer(ci); err != nil {
		return fmt.Errorf("%w. Give -credential-issuer, or -issuer if this "+
			"deployment is also the credential issuer", err)
	}

	// The client must exist, and must belong to this organisation. Checked now
	// rather than at redemption, where the wallet holder would be the one to
	// discover it — standing at a counter, with nothing to do about it.
	var clientOrg string
	var clientGrants []string
	if err := conn.QueryRow(ctx,
		`SELECT org_id::text, grant_types FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&clientOrg, &clientGrants); err != nil {
		return fmt.Errorf("no client %q is registered; the offer would redeem into "+
			"a token with no audience", clientID)
	}
	if clientOrg != orgID {
		return fmt.Errorf("client %q belongs to a different organisation than the "+
			"holder; a token minted for it would cross a tenant boundary", clientID)
	}
	// Checked at MINT time, not only at redemption. The person who finds out
	// otherwise is the holder, standing wherever they scanned the QR code, with
	// nothing they can do about it.
	if !slices.Contains(clientGrants, oid4vci.GrantType) {
		return fmt.Errorf("client %q is not registered for the pre-authorized code "+
			"grant, so this offer could not be redeemed. Add it with:\n"+
			"  signari client set-grants -client-id %s -grant-types %s",
			clientID, clientID, oid4vci.GrantType)
	}

	var userID string
	if err := conn.QueryRow(ctx, `
		SELECT id::text FROM core.users
		WHERE org_id = $1::uuid AND lower(email) = lower($2)`,
		orgID, strings.TrimSpace(email)).Scan(&userID); err != nil {
		return fmt.Errorf("no user %q in that organisation", email)
	}

	code, codeHash, err := store.NewPreAuthCode()
	if err != nil {
		return err
	}

	var tx *oid4vci.TxCode
	var txPlain string
	var txHash []byte
	if wantTxCode {
		txPlain, txHash, err = store.NewTxCode(txLength)
		if err != nil {
			return err
		}
		tx = &oid4vci.TxCode{
			InputMode: oid4vci.InputNumeric,
			Length:    txLength,
			Description: fmt.Sprintf("Enter the %d-digit code from the issuer",
				txLength),
		}
	}

	// §4.1.1: the ids "each identify one of the keys in the name/value pairs
	// stored in the credential_configurations_supported Credential Issuer
	// metadata". Checked here, where the configurations are reachable.
	//
	// Without it a typo produces a perfectly well-formed offer. The holder scans
	// it, authenticates, redeems the pre-authorized code -- and the credential
	// endpoint answers unsupported_credential_type, after everything they were
	// asked to do has been done correctly. The failure is maximally late and
	// lands on the wallet, which is the one component that did nothing wrong.
	configured, cerr := store.CredentialConfigurations(ctx, conn, orgID)
	if cerr != nil {
		return fmt.Errorf("loading credential configurations: %w", cerr)
	}
	var unknown []string
	for _, id := range ids {
		if _, ok := configured[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(configured))
		for id := range configured {
			known = append(known, id)
		}
		sort.Strings(known)
		if len(known) == 0 {
			return fmt.Errorf("this organisation issues no credentials, so an offer "+
				"naming %s could not be redeemed. Configure one first with "+
				"`signari credential config set`", strings.Join(unknown, ", "))
		}
		return fmt.Errorf("no credential configuration named %s; this issuer "+
			"advertises %s", strings.Join(unknown, ", "), strings.Join(known, ", "))
	}

	offer, err := oid4vci.BuildOffer(ci, ids, code, tx)
	if err != nil {
		return err
	}
	if err := store.NewPreAuthorizedCode(ctx, conn, orgID, userID, clientID,
		codeHash, ids, tx, txHash, ttl); err != nil {
		return err
	}

	blob, err := json.Marshal(offer)
	if err != nil {
		return err
	}

	fmt.Printf("credential offer for %s\n", email)
	fmt.Printf("  issuer    : %s\n", ci)
	fmt.Printf("  credential: %s\n", strings.Join(ids, ", "))
	fmt.Printf("  expires   : %s from now\n", ttl)
	fmt.Printf("\n%s\n", blob)
	// §G.7.1: the wallet is invoked with the offer by value in a query
	// parameter. Printed rather than rendered as a QR code, because whatever
	// puts this on a screen is the operator's own front desk software, and a
	// terminal is not where a holder scans anything.
	fmt.Printf("\n%s://?credential_offer=%s\n",
		oid4vci.CredentialOfferURIScheme, url.QueryEscape(string(blob)))
	if txPlain != "" {
		// Deliberately separate from everything above. §3.5: the transaction code
		// "MUST be sent via a different channel than the Credential Offer" —
		// printing it next to the offer for somebody to copy into the same
		// message would defeat the entire mechanism.
		fmt.Printf("\ntransaction code: %s\n", txPlain)
		fmt.Printf("  Send this to the holder by a DIFFERENT channel than the offer.\n")
		fmt.Printf("  It exists to stop somebody who photographed the QR code from\n")
		fmt.Printf("  redeeming it, so delivering both together protects nothing.\n")
		fmt.Printf("  %d wrong attempts end the offer.\n", oid4vci.MaxTxCodeAttempts)
	}
	return nil
}

// knownGrantTypes are the grants the token endpoint dispatches.
//
// Listed so `client set-grants` can refuse a typo. A grant type recorded on a
// client but never dispatched is a registration that looks like it did
// something, and the operator finds out at the first token request.
var knownGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"client_credentials",
	oauth.GrantTypeDeviceCode,
	oauth.GrantTypeTokenExchange,
	oid4vci.GrantType,
}

// clientSetGrants replaces the grant types a client may use.
//
// RFC 6749 §5.2: `unauthorized_client` is "The authenticated client is not
// authorized to use this authorization grant type" -- so which grants a client
// may use is registration data, and there was no way to set it. Every client
// carried the column default, which is why the device grant appeared to work
// for clients that were never registered for it: nothing checked.
func clientSetGrants(ctx context.Context, conn *pgx.Conn, clientID, grants string) error {
	if clientID == "" {
		return fmt.Errorf("give -client-id")
	}
	wanted := splitList(grants)
	if len(wanted) == 0 {
		return fmt.Errorf("give -grant-types, comma separated. A client with no "+
			"grant types can obtain no tokens at all; if that is what you mean, "+
			"disable the client instead.\n  known: %s",
			strings.Join(knownGrantTypes, ", "))
	}
	for _, g := range wanted {
		if !slices.Contains(knownGrantTypes, g) {
			return fmt.Errorf("%q is not a grant type this server dispatches. "+
				"Recording it would look like a registration and do nothing.\n"+
				"  known: %s", g, strings.Join(knownGrantTypes, ", "))
		}
	}
	// Token exchange is authorised by its own column, because the grant type
	// alone cannot say which audiences a client may exchange for.
	if slices.Contains(wanted, oauth.GrantTypeTokenExchange) {
		fmt.Printf("note: token exchange is additionally gated by may_exchange and\n" +
			"      the client's permitted audiences; this flag does not set those.\n")
	}
	tag, err := conn.Exec(ctx,
		`UPDATE core.clients SET grant_types = $2 WHERE client_id = $1`,
		clientID, wanted)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}
	fmt.Printf("client %s\n  grant types: %s\n", clientID, strings.Join(wanted, ", "))
	return nil
}

// rarCommonFields are §2.2's common data fields, the only ones a type may
// declare. A field outside this set could never be validated, and a registration
// that cannot be validated is one that accepts anything.
var rarCommonFields = []string{"locations", "actions", "datatypes", "identifier", "privileges"}

// rarRegister records an RFC 9396 authorization details type.
//
// §10 says "The registration of authorization details types with the AS is
// outside the scope of this specification", so this command is our answer to a
// question the RFC deliberately leaves open. It registers FIELDS, not value
// schemas: §2.2 says the allowable values "are determined by the API being
// protected", which this server cannot check, and a validator that pretended to
// would look stricter than it is.
func rarRegister(ctx context.Context, conn *pgx.Conn, orgID, typ, fields, required, desc string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	if strings.TrimSpace(typ) == "" {
		return fmt.Errorf("give -type, the identifier clients will send in " +
			"authorization_details")
	}
	f := splitList(fields)
	if len(f) == 0 {
		return fmt.Errorf("give -fields: which of %s this type uses. A type with no "+
			"fields carries no permission and could only ever authorise nothing",
			strings.Join(rarCommonFields, ", "))
	}
	req := splitList(required)
	for _, name := range append(append([]string{}, f...), req...) {
		if !slices.Contains(rarCommonFields, name) {
			return fmt.Errorf("%q is not one of RFC 9396 section 2.2's common data "+
				"fields (%s). A field outside that set cannot be validated, and this "+
				"server refuses any field it cannot validate",
				name, strings.Join(rarCommonFields, ", "))
		}
	}
	for _, name := range req {
		if !slices.Contains(f, name) {
			return fmt.Errorf("-required lists %q, which is not in -fields: a type "+
				"that requires a field it does not permit can never be satisfied", name)
		}
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.authorization_detail_types (org_id, type, fields, required, description)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5,''))
		ON CONFLICT (org_id, type) DO UPDATE
		SET fields = EXCLUDED.fields, required = EXCLUDED.required,
		    description = EXCLUDED.description`,
		orgID, typ, f, req, desc); err != nil {
		return fmt.Errorf("registering the type: %w", err)
	}

	fmt.Printf("authorization details type %s\n", typ)
	fmt.Printf("  fields   : %s\n", strings.Join(f, ", "))
	if len(req) > 0 {
		fmt.Printf("  required : %s\n", strings.Join(req, ", "))
	}
	fmt.Printf("\nNo client may request it yet. Allow one with:\n")
	fmt.Printf("  signari rar allow -client-id <id> -type %s\n", typ)
	return nil
}

// rarAllow lets one client request one registered type.
//
// An allow-list rather than "any registered type", for the same reason group
// release is one: a client that can request every permission a deployment has
// ever defined is a client whose consent screen can say anything.
func rarAllow(ctx context.Context, conn *pgx.Conn, clientID, typ string) error {
	if clientID == "" || typ == "" {
		return fmt.Errorf("give -client-id and -type")
	}
	var orgID string
	if err := conn.QueryRow(ctx,
		`SELECT org_id::text FROM core.authorization_detail_types
		 WHERE type = $1 LIMIT 1`, typ).Scan(&orgID); err != nil {
		return fmt.Errorf("no authorization details type %q is registered; run "+
			"`signari rar register` first", typ)
	}
	var clientOrg string
	if err := conn.QueryRow(ctx,
		`SELECT org_id::text FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&clientOrg); err != nil {
		return fmt.Errorf("no client %q", clientID)
	}
	if clientOrg != orgID {
		return fmt.Errorf("client %q belongs to a different organisation than the "+
			"type %q was registered in", clientID, typ)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.client_authorization_detail_types (client_id, org_id, type)
		VALUES ($1, $2::uuid, $3) ON CONFLICT DO NOTHING`,
		clientID, orgID, typ); err != nil {
		return err
	}
	fmt.Printf("client %s may now request authorization_details of type %s\n", clientID, typ)
	return nil
}

// rarList shows what is registered and who may ask for it.
func rarList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT t.type, t.fields, t.required, COALESCE(t.description,''),
		       COALESCE(array_agg(c.client_id) FILTER (WHERE c.client_id IS NOT NULL), '{}')
		FROM core.authorization_detail_types t
		LEFT JOIN core.client_authorization_detail_types c ON c.type = t.type
		GROUP BY t.type, t.fields, t.required, t.description
		ORDER BY t.type`)
	if err != nil {
		return err
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var typ, desc string
		var fields, required, clients []string
		if err := rows.Scan(&typ, &fields, &required, &desc, &clients); err != nil {
			return err
		}
		found = true
		fmt.Printf("%s\n", typ)
		if desc != "" {
			fmt.Printf("  %s\n", desc)
		}
		fmt.Printf("  fields   : %s\n", strings.Join(fields, ", "))
		if len(required) > 0 {
			fmt.Printf("  required : %s\n", strings.Join(required, ", "))
		}
		if len(clients) == 0 {
			fmt.Printf("  clients  : none -- no client can request this yet\n")
		} else {
			fmt.Printf("  clients  : %s\n", strings.Join(clients, ", "))
		}
	}
	if !found {
		fmt.Println("no authorization details types are registered")
	}
	return rows.Err()
}

// credentialClaims are the claim names a credential may carry.
//
// A fixed list, not "any column": every value here ends up inside a credential
// the holder can present to anybody, so what may appear is a decision rather
// than a projection of whatever the users table happens to hold.
var credentialClaims = []string{"sub", "email", "email_verified", "preferred_username"}

// credentialDefine registers a credential this issuer can mint.
//
// OID4VCI §12.2: the entry becomes one key of
// `credential_configurations_supported`, which is what a wallet reads to learn
// what it may ask for.
func credentialDefine(ctx context.Context, conn *pgx.Conn, orgID, configID, vct,
	always, selective string, lifetime time.Duration, displayName string) error {

	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	if strings.TrimSpace(configID) == "" {
		return fmt.Errorf("give -credential-configuration, the identifier a wallet " +
			"sends as credential_configuration_id")
	}
	if strings.TrimSpace(vct) == "" {
		return fmt.Errorf("give -vct, the credential type identifier. SD-JWT VC " +
			"section 3.2.2.1 requires a collision-resistant name, so use a URL you " +
			"control, e.g. https://example.com/identity_credential")
	}
	a, sel := splitList(always), splitList(selective)
	if len(a)+len(sel) == 0 {
		return fmt.Errorf("give -always and/or -selective: a credential carrying "+
			"no claims asserts nothing. Available: %s",
			strings.Join(credentialClaims, ", "))
	}
	for _, name := range append(append([]string{}, a...), sel...) {
		if !slices.Contains(credentialClaims, name) {
			return fmt.Errorf("%q is not a claim this issuer can put in a "+
				"credential. Available: %s", name, strings.Join(credentialClaims, ", "))
		}
	}
	for _, name := range a {
		if slices.Contains(sel, name) {
			return fmt.Errorf("%q is listed as both always-visible and selective; "+
				"revealing it would put the claim in the credential twice", name)
		}
	}

	var interval any
	if lifetime > 0 {
		interval = fmt.Sprintf("%d seconds", int(lifetime.Seconds()))
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.credential_configurations
			(org_id, config_id, vct, always_claims, selective_claims, lifetime, display_name)
		VALUES ($1::uuid, $2, $3, $4, $5, $6::interval, NULLIF($7,''))
		ON CONFLICT (org_id, config_id) DO UPDATE
		SET vct = EXCLUDED.vct, always_claims = EXCLUDED.always_claims,
		    selective_claims = EXCLUDED.selective_claims,
		    lifetime = EXCLUDED.lifetime, display_name = EXCLUDED.display_name`,
		orgID, configID, vct, a, sel, interval, displayName); err != nil {
		return fmt.Errorf("defining the credential: %w", err)
	}

	fmt.Printf("credential configuration %s\n", configID)
	fmt.Printf("  vct       : %s\n", vct)
	if len(a) > 0 {
		fmt.Printf("  always    : %s\n", strings.Join(a, ", "))
	}
	if len(sel) > 0 {
		fmt.Printf("  selective : %s\n", strings.Join(sel, ", "))
	}
	if lifetime > 0 {
		fmt.Printf("  valid for : %s\n", lifetime)
	}
	fmt.Printf("\nThe claims under `always` are visible to EVERY verifier the holder\n")
	fmt.Printf("presents to. Only the `selective` ones can be withheld.\n")
	return nil
}

// credentialList shows what this issuer publishes.
func credentialList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT config_id, format, vct, always_claims, selective_claims,
		       COALESCE(display_name,'')
		FROM core.credential_configurations ORDER BY config_id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var id, format, vct, display string
		var a, sel []string
		if err := rows.Scan(&id, &format, &vct, &a, &sel, &display); err != nil {
			return err
		}
		found = true
		fmt.Printf("%s (%s)\n", id, format)
		if display != "" {
			fmt.Printf("  %s\n", display)
		}
		fmt.Printf("  vct       : %s\n", vct)
		fmt.Printf("  always    : %s\n", strings.Join(a, ", "))
		fmt.Printf("  selective : %s\n", strings.Join(sel, ", "))
	}
	if !found {
		fmt.Println("this deployment issues no credentials")
	}
	return rows.Err()
}

// attesterAdd registers a trusted Client Attester,
// draft-ietf-oauth-attestation-based-client-auth-10 §7.1 rule 4.
//
// Without at least one of these, no attestation can verify -- rule 4 requires
// the signature to check out against "a known and trusted Client Attester", and
// trust here means somebody deliberately registered the key.
func attesterAdd(ctx context.Context, conn *pgx.Conn, orgID, name, jwksPath string) error {
	if orgID == "" || name == "" || jwksPath == "" {
		return fmt.Errorf("attester add needs --org, --name and --attester-jwks")
	}
	blob, err := os.ReadFile(jwksPath)
	if err != nil {
		return fmt.Errorf("reading the attester JWKS: %w", err)
	}

	// Parsed before storing, and checked for private keys.
	//
	// A JWKS that does not parse would be stored happily and then fail every
	// authentication at run time, with an error pointing at the client rather
	// than at this registration. And an attester "public" key file that actually
	// contains private keys is a mistake worth catching at the moment somebody
	// makes it: it would mean this server could mint attestations indistinguishable
	// from the attester's own, which is the trust separation ABCA exists to create.
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		return fmt.Errorf("the attester JWKS is not a JSON Web Key Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("the attester JWKS contains no keys")
	}
	for i, k := range set.Keys {
		if !k.IsPublic() {
			return fmt.Errorf("key %d in the attester JWKS is a PRIVATE key; register "+
				"only the attester's public keys, or this server could forge the "+
				"attestations it is supposed to be verifying", i)
		}
		if !k.Valid() {
			return fmt.Errorf("key %d in the attester JWKS is not usable", i)
		}
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.client_attesters (org_id, name, jwks)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (org_id, name) DO UPDATE SET jwks = EXCLUDED.jwks`,
		orgID, name, blob); err != nil {
		return fmt.Errorf("registering the client attester: %w", err)
	}
	fmt.Printf("registered client attester %q with %d key(s)\n", name, len(set.Keys))
	return nil
}

// attesterList shows who is trusted to vouch for clients.
func attesterList(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT org_id::text, name, jsonb_array_length(jwks->'keys'), created_at
		FROM core.client_attesters ORDER BY org_id, name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var org, name string
		var keys int
		var created time.Time
		if err := rows.Scan(&org, &name, &keys, &created); err != nil {
			return err
		}
		found = true
		fmt.Printf("%s  %-30s %d key(s)  %s\n", org, name, keys, created.Format(time.RFC3339))
	}
	if !found {
		fmt.Println("no client attesters registered; attestation-based client " +
			"authentication cannot verify anything until one is added")
	}
	return rows.Err()
}

// warnUndriven says which flows in a file were stored and will not run.
//
// Printed at the moment of installation, not only when a file is checked. An
// operator who applies a recovery flow has just been told it is deployed, and it
// is not: `/recover` is a hardcoded journey that never reads this document.
//
// The engine drives authentication, enrolment and recovery flows. The only
// designation it does not is `unenrolment`, and the reason is that there is no
// self-service unenrolment journey to drive -- see flow.Designation.Driven.
func warnUndriven(f *flow.File) {
	var undriven []string
	for i := range f.Flows {
		if !f.Flows[i].On.Driven() {
			undriven = append(undriven,
				fmt.Sprintf("%s (%s)", f.Flows[i].Name, f.Flows[i].On))
		}
	}
	if len(undriven) == 0 {
		return
	}
	fmt.Printf("\n  WARNING: %d flow(s) in this file are stored and NOT executed:\n",
		len(undriven))
	for _, u := range undriven {
		fmt.Printf("    - %s\n", u)
	}
	fmt.Printf("  This engine drives %s, %s and %s flows. It has no self-service\n"+
		"  %s journey at all -- deleting an account is `signari erase subject`\n"+
		"  and the admin API, which are operator actions rather than a sequence a\n"+
		"  subject walks -- so a flow declaring one is stored, checked, and has no\n"+
		"  endpoint to govern.\n",
		flow.Authentication, flow.Enrolment, flow.Recovery, flow.Unenrolment)
}

// clientSetDPoP pins a client to DPoP, per RFC 9449 §5.2.
//
//	"dpop_bound_access_tokens: A boolean value specifying whether the client
//	always uses DPoP for token requests ... If the value is true, the
//	authorization server MUST reject token requests from the client that do not
//	contain the DPoP header."
//
// Without this, whether a token is sender-constrained is decided per request by
// whether a proof happened to be attached. A client that means to be bound on
// every request cannot say so, and one request that omits the header quietly
// yields an ordinary bearer token -- a downgrade that needs no attack on DPoP,
// only the absence of a proof.
func clientSetDPoP(ctx context.Context, conn *pgx.Conn, clientID string, required bool) error {
	if clientID == "" {
		return fmt.Errorf("give -client")
	}
	tag, err := conn.Exec(ctx, `
		UPDATE core.clients SET dpop_bound_access_tokens = $2, updated_at = now()
		WHERE client_id = $1`, clientID, required)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}
	if required {
		fmt.Printf("%s now requires a DPoP proof on every token request\n", clientID)
	} else {
		fmt.Printf("%s no longer requires DPoP; tokens are bound only when a proof is sent\n", clientID)
	}
	return nil
}

func clientSetExchangeContainment(ctx context.Context, conn *pgx.Conn, clientID string, on bool) error {
	if clientID == "" {
		return fmt.Errorf("give -client")
	}
	tag, err := conn.Exec(ctx, `
		UPDATE core.clients SET exchange_requires_audience_match = $2, updated_at = now()
		WHERE client_id = $1`, clientID, on)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}
	if on {
		fmt.Printf("%s may now only exchange subject tokens it holds or is named in the audience of\n", clientID)
	} else {
		fmt.Printf("%s may exchange any valid subject token, bounded by its audience allow-list\n", clientID)
	}
	return nil
}
