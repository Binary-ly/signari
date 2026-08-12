package mail

import (
	"context"
	"fmt"
	"net"
	"strings"
)


// Severity ranks a finding by what it does to delivery.
type Severity string

const (
	// Fail means mail will be rejected or reliably junked.
	Fail Severity = "fail"
	// Warn means it will probably arrive today and is fragile.
	Warn Severity = "warn"
	Pass Severity = "pass"
)

// Finding is one checked property, with the fix rather than just the verdict.
type Finding struct {
	Check    string
	Severity Severity
	Detail   string
	// Fix is the actual DNS record to publish. A diagnosis an operator has to go
	// research is a diagnosis most operators do not act on.
	Fix string
}

// Report is the result of a preflight.
type Report struct {
	Domain   string
	Findings []Finding
}

// Deliverable reports whether anything would stop mail arriving.
func (r Report) Deliverable() bool {
	for _, f := range r.Findings {
		if f.Severity == Fail {
			return false
		}
	}
	return true
}

// Preflight checks the sending domain's DNS.
//
// The domain comes from the envelope sender, because that is what receivers
// check SPF against -- not the From header, and not the SMTP host.
func Preflight(ctx context.Context, fromAddr, dkimSelector string) Report {
	domain := fromAddr
	if i := strings.LastIndex(fromAddr, "@"); i >= 0 {
		domain = fromAddr[i+1:]
	}
	rep := Report{Domain: domain}
	res := net.Resolver{}

	// --- SPF ---------------------------------------------------------------
	txt, err := res.LookupTXT(ctx, domain)
	spf := ""
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
			break
		}
	}
	switch {
	case err != nil:
		rep.add("SPF", Fail, fmt.Sprintf("could not read TXT records for %s: %v", domain, err), "")
	case spf == "":
		rep.add("SPF", Fail, "no SPF record: receivers cannot tell that your mail server is "+
			"allowed to send as this domain, and most will junk or reject it",
			fmt.Sprintf(`%s.  TXT  "v=spf1 include:<your-provider> -all"`, domain))
	case strings.Contains(spf, "+all"):
		// Worse than having none: it authorises the entire internet to send as
		// this domain, and receivers treat it as a spam signal in its own right.
		rep.add("SPF", Fail, "SPF ends in +all, which authorises anyone on the internet to send "+
			"as this domain", strings.Replace(spf, "+all", "-all", 1))
	case strings.Contains(spf, "~all"):
		rep.add("SPF", Warn, "SPF ends in ~all (softfail). Mail from unauthorised servers is "+
			"accepted and marked, which weakens the record to a suggestion",
			strings.Replace(spf, "~all", "-all", 1))
	case strings.Contains(spf, "-all"):
		rep.add("SPF", Pass, spf, "")
	default:
		rep.add("SPF", Warn, "SPF has no explicit all mechanism, so unauthorised senders are "+
			"neither rejected nor marked", spf+" -all")
	}

	// --- DKIM --------------------------------------------------------------
	if dkimSelector == "" {
		rep.add("DKIM", Warn, "no selector configured, so DKIM cannot be checked. Your provider "+
			"gives you one (often 'resend', 'pm', 'google' or 's1')", "")
	} else {
		host := dkimSelector + "._domainkey." + domain
		rec, err := res.LookupTXT(ctx, host)
		joined := strings.Join(rec, "")
		switch {
		case err != nil || joined == "":
			rep.add("DKIM", Fail, fmt.Sprintf("no DKIM key at %s: messages are unsigned, so "+
				"receivers cannot verify they were not altered, and DMARC cannot pass", host),
				fmt.Sprintf(`%s.  TXT  "v=DKIM1; k=rsa; p=<public key from your provider>"`, host))
		case !strings.Contains(joined, "p="):
			rep.add("DKIM", Fail, fmt.Sprintf("the record at %s has no public key (p=)", host), "")
		default:
			rep.add("DKIM", Pass, "signing key published at "+host, "")
		}
	}

	// --- DMARC -------------------------------------------------------------
	dmarc, err := res.LookupTXT(ctx, "_dmarc."+domain)
	joined := strings.Join(dmarc, "")
	switch {
	case err != nil || joined == "":
		// Gmail and Yahoo have required DMARC for bulk senders since 2024, and
		// treat its absence as a negative signal for everyone else.
		rep.add("DMARC", Fail, "no DMARC record: major providers now require one, and without it "+
			"nobody can tell a forged message from a real one",
			fmt.Sprintf(`_dmarc.%s.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@%s"`, domain, domain))
	case strings.Contains(joined, "p=none"):
		rep.add("DMARC", Warn, "DMARC policy is p=none, which asks receivers to report forgeries "+
			"but not to act on them. Correct while you are collecting reports; move to quarantine "+
			"once they look clean", strings.Replace(joined, "p=none", "p=quarantine", 1))
	default:
		rep.add("DMARC", Pass, joined, "")
	}

	// --- MX ----------------------------------------------------------------
	// Not required to SEND, but its absence means bounces and replies go nowhere,
	// and a domain that cannot receive mail is itself a spam signal.
	if mx, err := res.LookupMX(ctx, domain); err != nil || len(mx) == 0 {
		rep.add("MX", Warn, "no MX record: this domain cannot receive mail, so bounces and "+
			"replies are lost and some receivers score the domain down for it", "")
	} else {
		rep.add("MX", Pass, fmt.Sprintf("%d mail exchanger(s)", len(mx)), "")
	}

	return rep
}

func (r *Report) add(check string, sev Severity, detail, fix string) {
	r.Findings = append(r.Findings, Finding{Check: check, Severity: sev, Detail: detail, Fix: fix})
}
