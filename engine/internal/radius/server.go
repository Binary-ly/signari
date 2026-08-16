package radius

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// Authenticator verifies a credential.
//
// The same interface shape as the LDAP shim, and for the same reason: every way
// into this product must go through one credential path, with the same Argon2
// parameters, the same throttling and the same audit trail. A protocol front end
// with its own quiet password check routes around every control the rest of the
// system has.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) error
}

// Client is a network device permitted to ask.
type Client struct {
	// Net is the range the device may connect from. RADIUS has no client
	// certificate and no handshake -- the shared secret and the source address
	// are the only two things distinguishing a real switch from anybody who can
	// send a UDP packet.
	Net    *net.IPNet
	Secret string
	Name   string
}

// Config is one listener.
type Config struct {
	Clients []Client
	// ReadTimeout bounds a single exchange.
	ReadTimeout time.Duration
	// EAPTLS enables certificate-based login. nil means EAP requests are
	// refused rather than answered with something weaker: a supplicant that
	// asks for EAP and is offered a password method has been downgraded, and
	// the whole point of EAP-TLS is that there is no password to downgrade to.
	EAPTLS *EAPTLSConfig
}

// Server answers Access-Requests.
type Server struct {
	cfg  Config
	auth Authenticator
	log  *slog.Logger

	// clientsMu guards the device list, which is REPLACED while the listener is
	// running.
	//
	// Read once at startup, disabling a device did nothing until a restart: the
	// listener kept answering an access point whose access had been revoked.
	// The same shape as the signing keys, which were also read once and made
	// key rotation a ceremony with no effect.
	clientsMu sync.RWMutex
	clients   []Client

	eapTLS   *EAPTLSConfig
	sessions *eapSessions
}

// ReplaceClients swaps the devices this server answers.
//
// # An empty list is honoured, and that took a correction
//
// The first version refused it, reasoning that a server trusting nobody is a
// total outage and that an empty result was more likely a failed read than a
// deliberate removal. That reasoning was borrowed from the directory sync,
// where an empty fetch really can mean a paginated read that stopped early --
// and it does not transfer. A single SQL query either succeeds or returns an
// error; there is no partial success to mistake for emptiness.
//
// So an empty list is a definite answer: every device has been disabled. The
// guard blocked exactly the operation it was written alongside -- revoking the
// last access point did nothing, because the reload that would have applied it
// was refused.
//
// It is logged at WARN, because "no devices" means network login is off for
// everybody and that should be visible without going looking.
//
// New() still refuses an empty list at STARTUP. A listener coming up with
// nothing configured is almost certainly a misconfiguration, and saying so
// immediately is more useful than serving a port that answers no one.
func (s *Server) ReplaceClients(clients []Client) error {
	for _, c := range clients {
		if err := ValidSecret(c.Secret); err != nil {
			return err
		}
		if c.Net == nil {
			return fmt.Errorf("RADIUS client %q has no network", c.Name)
		}
	}
	s.clientsMu.Lock()
	prev := len(s.clients)
	s.clients = clients
	s.clientsMu.Unlock()

	if len(clients) == 0 && prev > 0 {
		s.log.Warn("every RADIUS device is now disabled; this listener will " +
			"answer nobody")
	}
	return nil
}

func New(cfg Config, auth Authenticator, log *slog.Logger) (*Server, error) {
	if len(cfg.Clients) == 0 {
		return nil, errors.New("no RADIUS clients configured; a server that trusts " +
			"nobody answers nobody, and one that trusts everybody is an authentication " +
			"oracle for the whole network")
	}
	for _, c := range cfg.Clients {
		if err := ValidSecret(c.Secret); err != nil {
			return nil, err
		}
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.EAPTLS != nil {
		switch {
		case cfg.EAPTLS.ClientCAs == nil:
			return nil, errors.New("EAP-TLS needs client CAs: without them there is " +
				"nothing to verify a supplicant certificate against, and the handshake " +
				"would authenticate anybody who presents any certificate")
		case cfg.EAPTLS.Auth == nil:
			return nil, errors.New("EAP-TLS needs a certificate authenticator to map a " +
				"verified certificate to a user")
		case len(cfg.EAPTLS.Certificate.Certificate) == 0:
			return nil, errors.New("EAP-TLS needs a server certificate; supplicants " +
				"verify it, and one they do not trust makes every login fail")
		}
	}
	return &Server{cfg: cfg, auth: auth, log: log, clients: cfg.Clients,
		eapTLS: cfg.EAPTLS, sessions: newEAPSessions()}, nil
}

// clientFor finds the configured device for a source address.
func (s *Server) clientFor(addr net.Addr) (Client, bool) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return Client{}, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return Client{}, false
	}
	s.clientsMu.RLock()
	clients := s.clients
	s.clientsMu.RUnlock()

	for _, c := range clients {
		if c.Net.Contains(ip) {
			return c, true
		}
	}
	return Client{}, false
}

// Serve answers packets until the context is cancelled.
func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, maxPacket)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		// Handled inline rather than in a goroutine per packet. UDP has no
		// handshake, so a goroutine per datagram is a spawn primitive for anybody
		// who can send packets -- and the work here is one Argon2 verification,
		// which is deliberately expensive.
		s.handle(ctx, conn, addr, append([]byte(nil), buf[:n]...))
	}
}

func (s *Server) handle(ctx context.Context, conn net.PacketConn, addr net.Addr, raw []byte) {
	client, ok := s.clientFor(addr)
	if !ok {
		// Silence, not a rejection. An unconfigured source gets no answer at all:
		// replying would confirm a RADIUS server is here and turn the port into a
		// discovery tool.
		s.log.Info("RADIUS packet from an unconfigured source", "addr", addr.String())
		return
	}
	secret := []byte(client.Secret)

	p, err := Decode(raw)
	if err != nil {
		s.log.Info("malformed RADIUS packet", "client", client.Name, "err", err)
		return
	}
	if p.Code != CodeAccessRequest {
		// Only Access-Request. Accounting and CoA are separate protocols with
		// separate risks, and answering a code we do not implement invites a
		// device to believe we do.
		return
	}

	// THE Blast-RADIUS check, before anything in the packet is believed.
	if err := p.VerifyMessageAuthenticator(secret); err != nil {
		s.log.Warn("RADIUS request refused", "client", client.Name, "err", err)
		return
	}

	// EAP first. A request carrying EAP-Message is an EAP conversation and has
	// no User-Password at all, so the password path below would reject it for
	// the wrong reason and tell the supplicant nothing useful.
	if eap, ok := p.EAPMessage(); ok {
		s.handleEAP(conn, addr, p, secret, client, eap)
		return
	}

	username, ok := p.Attr(AttrUserName)
	if !ok || len(username) == 0 {
		s.reject(conn, addr, p, secret, "no user name")
		return
	}
	if p.Count(AttrUserName) > 1 {
		s.reject(conn, addr, p, secret, "more than one user name")
		return
	}

	password, err := p.DecodePassword(secret)
	if err != nil {
		s.reject(conn, addr, p, secret, "no usable password")
		return
	}
	if password == "" {
		// An empty password authenticates nobody, the same rule the LDAP shim
		// applies to an unauthenticated bind.
		s.reject(conn, addr, p, secret, "empty password")
		return
	}

	if err := s.auth.Authenticate(ctx, strings.TrimSpace(string(username)), password); err != nil {
		s.log.Info("RADIUS authentication failed", "client", client.Name,
			"username", string(username))
		s.reject(conn, addr, p, secret, "authentication failed")
		return
	}

	s.log.Info("RADIUS authentication succeeded", "client", client.Name,
		"username", string(username))
	out, err := Response(p, CodeAccessAccept, secret, nil)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(out, addr)
}

// reject answers Access-Reject.
//
// The reply message is deliberately the same for every failure. A device
// displays it to whoever is typing, so distinguishing "no such user" from "wrong
// password" makes the network login screen a user-enumeration oracle.
func (s *Server) reject(conn net.PacketConn, addr net.Addr, p *Packet, secret []byte, why string) {
	s.log.Debug("RADIUS reject", "reason", why)
	out, err := Response(p, CodeAccessReject, secret, []Attribute{
		{Type: AttrReplyMessage, Value: []byte("Authentication failed")},
	})
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(out, addr)
}
