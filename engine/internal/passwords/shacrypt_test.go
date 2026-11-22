package passwords

import (
	"errors"
	"testing"
)

// glibc SHA-crypt ($5$, $6$), checked against two implementations that are
// not this one (4.09): OpenSSL 3.6.3's `openssl passwd -5|-6 -salt <s> <pw>`
// and PHP 8.4.18's crypt(), whose SHA-crypt is its own rather than the C
// library's. They agree with each other wherever both apply; PHP alone made
// the rounds= vectors, since `openssl passwd` cannot set them. A verifier that
// agrees only with itself would tell every person imported from /etc/shadow
// or an LDAP directory that their password was wrong.
var shaCryptVectors = []struct{ password, stored string }{
	// OpenSSL, salt "toolongsaltstringthatistruncated" (cut to 16).
	{"a", "$5$toolongsaltstrin$Y5wGGKUH2v6z1saSwcVfFuvi2xIrSi6slnw8Ye/8aB9"},
	{"Hello world!", "$5$toolongsaltstrin$0vuwUia3Nx9V/DqToMS8YLcfXpEXmSaC8wgguLIbus2"},
	{"we have a short salt string but not a short password",
		"$5$toolongsaltstrin$MFW7Vdfl6BBsKShK1Hhi8amLns1JdP1B6EZH7.YwQU8"},
	{"a very much longer text to encrypt.  This one even stretches over morethan one line.",
		"$5$toolongsaltstrin$/l//PlTmqUGB3Tk2aYj...M0rpL6G2kN3R1w7KehV/1"},
	{"this is a password that is exactly sixty-four bytes long!!!!!!!!",
		"$5$toolongsaltstrin$2.npXFq.QJZ5E4IwlkPFVK8Tac1RynAdUUYbS05Nq12"},
	{"a", "$6$toolongsaltstrin$W0TyyDfdc.ZBRsHnHME2Ugypd.smPN.uHqrgdyfui3u7bPN0H9xGtDW230eR8VbWiFACsbCXoTT/lgwwKktDv1"},
	{"Hello world!", "$6$toolongsaltstrin$iGlL7EUUfzNQx59x3ydJZ.zXPMUu1dOynSEl/vcNhLlas77qD0DzRswhhB6LdrXTz250at0syAfUXra.XrxAI1"},
	{"we have a short salt string but not a short password",
		"$6$toolongsaltstrin$CsXGH/Hv7LfzV7cz4e5PZ25Frby4INJn6I9bBUm6PHYCfL3ryXe64vEUIDqe.2fTY/Xn2QWl570cYoUZo3uIR1"},
	{"a very much longer text to encrypt.  This one even stretches over morethan one line.",
		"$6$toolongsaltstrin$d83lI1f8Dmg5G54BIEUCk.d1wzcvMvHiDIygj5z1mZBp8sK1sb1wb5GVvQ7hgyXszzhH1BdryFoyDxA5CIFdb1"},
	{"this is a password that is exactly sixty-four bytes long!!!!!!!!",
		"$6$toolongsaltstrin$goIEGX99P2GYkdrx/tZd7.wGEn71BPmfk8TyG.XzaUsKnwCV3lUTWN/r2kdxw1V3zM5YRkK9YWI9/es44wHqD1"},
	{"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
	{"correct-horse", "$6$abcdefghijklmnop$nmNyAaH/6gBRHJoLPwH1/AtpW5kLUN.F9idLxlyXJao/QMkkQWfPO87.ci./j.XYEWTw7OiynLl88jj3T2bDX1"},
	// PHP: rounds stated.
	{"Hello world!", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
	{"Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
	{"Hello world!", "$6$rounds=1400$anotherlongsalts$5FGyu8c4BZDX4wJgs0Un26YOw2XibT5eTkHF1I1aP3QqStoJI9BHD2YPJYsAjEePVGUyBjdZxcNqMWlrrbIOC."},
	{"Hello world!", "$6$rounds=5000$toolongsaltstrin$iGlL7EUUfzNQx59x3ydJZ.zXPMUu1dOynSEl/vcNhLlas77qD0DzRswhhB6LdrXTz250at0syAfUXra.XrxAI1"},
	{"correct-horse", "$6$rounds=5000$abcdefghijklmnop$nmNyAaH/6gBRHJoLPwH1/AtpW5kLUN.F9idLxlyXJao/QMkkQWfPO87.ci./j.XYEWTw7OiynLl88jj3T2bDX1"},
}

func TestSHACryptAgreesWithTwoOtherImplementations(t *testing.T) {
	for _, v := range shaCryptVectors {
		if err := verifySHACrypt(v.stored, v.password); err != nil {
			t.Errorf("%.40s... did not verify %q: %v", v.stored, v.password, err)
		}
		if err := verifySHACrypt(v.stored, v.password+"x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("%.40s... verified the wrong password", v.stored)
		}
	}
}
