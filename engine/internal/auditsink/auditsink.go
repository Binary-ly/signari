// Package auditsink forwards audit events to a logically separate system -- a
// syslog collector or a SIEM's HTTP endpoint -- so a host breach does not put the
// evidence and the incident in one blast radius (OWASP ASVS V16.4.3).
//
// A Sink is deliberately small: it takes a batch and either delivers it or
// returns an error. The forwarder that drives it (in the serve loop) owns the
// cursor and the retry, so a Sink never has to think about ordering or
// at-least-once -- it delivers what it is given, and a failure means "try again",
// which the forwarder does by not advancing the cursor.
package auditsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/safedial"
)

// Sink delivers a batch of audit records to an external destination.
type Sink interface {
	// Emit delivers every record or returns an error. It must be all-or-nothing
	// from the forwarder's point of view: a partial success it reports as an error
	// causes the whole batch to be retried, which is safe because a receiver is
	// expected to dedupe on the record id.
	Emit(ctx context.Context, records []audit.StreamRecord) error
	// Describe names the destination for logs and `signari doctor`, with any
	// secret redacted.
	Describe() string
}

// WebhookSink POSTs records as newline-delimited JSON to a SIEM endpoint.
//
// NDJSON rather than one array: a SIEM ingest usually reads a line at a time, and
// a partial POST then yields whole records rather than a truncated array that
// parses as nothing.
type WebhookSink struct {
	URL    string
	Token  string // optional bearer, sent as Authorization if set
	client *http.Client
}

// NewWebhookSink builds a webhook sink, refusing a URL that resolves into the
// private network -- the same SSRF guard every other outbound path here uses,
// because the destination is operator-configured but still a URL.
func NewWebhookSink(url, token string) (*WebhookSink, error) {
	if err := safedial.CheckURL(url); err != nil {
		return nil, fmt.Errorf("audit webhook: %w", err)
	}
	return &WebhookSink{URL: url, Token: token, client: safedial.Client(10 * time.Second)}, nil
}

func (s *WebhookSink) Describe() string { return "webhook (" + redactURL(s.URL) + ")" }

func (s *WebhookSink) Emit(ctx context.Context, records []audit.StreamRecord) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encoding an audit record: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting audit records: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("audit webhook returned %d", resp.StatusCode)
	}
	return nil
}

// SyslogSink writes RFC 5424 lines to a syslog collector over TCP.
//
// TCP, not UDP: an audit trail forwarded over a datagram that may be dropped is a
// gap nobody can see, and the whole point of forwarding is that the copy survives
// what happens to the origin. A new connection per batch keeps the sink stateless
// and lets a collector that restarted be reconnected to without the forwarder
// tracking socket health.
type SyslogSink struct {
	Addr string // host:port of the syslog collector
	TLS  bool   // wrap the connection in TLS when the collector expects it
	Host string // the hostname to stamp into each line
}

func NewSyslogSink(addr string, useTLS bool, hostname string) *SyslogSink {
	if hostname == "" {
		hostname = "signari"
	}
	return &SyslogSink{Addr: addr, TLS: useTLS, Host: hostname}
}

func (s *SyslogSink) Describe() string {
	if s.TLS {
		return "syslog+tls (" + s.Addr + ")"
	}
	return "syslog (" + s.Addr + ")"
}

func (s *SyslogSink) Emit(ctx context.Context, records []audit.StreamRecord) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	var err error
	if s.TLS {
		conn, err = tls.DialWithDialer(&d, "tcp", s.Addr, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", s.Addr)
	}
	if err != nil {
		return fmt.Errorf("connecting to syslog: %w", err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	var buf bytes.Buffer
	for _, r := range records {
		buf.WriteString(syslogLine(s.Host, r))
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("writing to syslog: %w", err)
	}
	return nil
}

// syslogLine renders one RFC 5424 message with the event as a JSON payload.
//
// Octet-counting framing (RFC 6587) -- "<len> <message>" -- because a collector
// reading a stream of messages over TCP needs to know where each ends, and the
// JSON payload can contain newlines that newline-framing would split on.
func syslogLine(host string, r audit.StreamRecord) string {
	const facility, severity = 13, 6 // log audit / informational
	pri := facility*8 + severity
	payload, _ := json.Marshal(r)
	// VERSION=1, ISO-8601 time, host, app-name signari, procid/msgid/sd absent (-)
	msg := fmt.Sprintf("<%d>1 %s %s signari - %s - %s",
		pri, r.OccurredAt.UTC().Format(time.RFC3339), host, r.EventType, payload)
	return fmt.Sprintf("%d %s", len(msg), msg)
}

func redactURL(u string) string {
	if i := strings.Index(u, "?"); i >= 0 {
		return u[:i] + "?…"
	}
	return u
}
