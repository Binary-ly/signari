package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"signari.dev/engine/internal/ech"
)

// echNew makes an Encrypted Client Hello key (internal/ech) and writes its file,
// which only the engine reads, and prints the ECHConfigList to publish: the
// part a client needs, which is public. Needs no database.
func echNew(out io.Writer, publicName, path string, configID int) error {
	if path == "" {
		return errors.New("give -out, the file to write the key to; a private key is not printed")
	}
	if configID < -1 || configID > 255 {
		return errors.New("-config-id is 0 to 255")
	}
	if configID == -1 {
		// Random, so that a key made later for the same listener is unlikely to
		// share its id: clients name the key they used by it alone, and Load
		// refuses two keys with one.
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		configID = int(b[0])
	}
	k, err := ech.New(publicName, byte(configID))
	if err != nil {
		return err
	}
	data, err := k.MarshalPEM()
	if err != nil {
		return err
	}
	list, err := k.List()
	if err != nil {
		return err
	}
	// O_EXCL: a key in use is never overwritten by a typo, since clients holding
	// its configuration would then be refused until the DNS caught up.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 G703 -- the operator names it, with -out
	if err != nil {
		return fmt.Errorf("writing the key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, `ECH key %s written: config id %d, public name %s.

Publish its configuration in the HTTPS record of the name people sign in at
(RFC 9848), for example:

  auth.example.com. 300 IN HTTPS 1 . ech="%s"

and start the engine with SIGNARI_TLS_ECH_KEYS=%s, before any older key files,
which keep working for clients holding the old record. The listener then takes
TLS 1.3 only, and needs a certificate for %s as well as for its own name.
`, path, configID, publicName, base64.StdEncoding.EncodeToString(list), path, publicName)
	return err
}
