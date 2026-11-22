package keys

import (
	"fmt"
	"os"
	"strings"
)

// LoadRootKey reads a root key from the variable `value` holds, or from the
// file the variable `file` names (3.12), labelled by the variable `ref`.
//
// The key could only come from the environment, which the process passes to
// every child it starts, a crash reporter may dump and a container runtime
// shows to anyone who may inspect it. A file can be a mounted secret readable
// by this process alone. So a file that its group or anybody else may read is
// refused rather than read: the root key opens every signing key and every
// sealed secret, and a world-readable copy of it is the leak this exists to
// avoid. Both set is refused too, since the two could disagree and nothing
// would say which one won.
func LoadRootKey(getenv func(string) string, value, file, ref string) (*RootKey, error) {
	b64, path := getenv(value), getenv(file)
	switch {
	case b64 != "" && path != "":
		return nil, fmt.Errorf("%s and %s are both set; set one, so there is no question of which "+
			"key this process runs on", value, file)
	case path != "":
		var err error
		if b64, err = secretFile(file, path, "The root key opens every signing key"); err != nil {
			return nil, err
		}
	case b64 == "":
		return nil, fmt.Errorf("%s is unset (32 random bytes, base64), and so is %s -- generate one with:\n"+
			"  head -c 32 /dev/urandom | base64", value, file)
	}
	return NewRootKeyFromBase64(getenv(ref), b64)
}

// secretFile reads a secret from the file the variable file names, path, and
// refuses one its group or others may read; why names what the secret opens.
func secretFile(file, path, why string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", file, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s names %s, which its group or others may read (mode %04o); "+
			"make it 0400 or 0600 for the user this runs as. %s", file, path, perm, why)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the operator names the file
	if err != nil {
		return "", fmt.Errorf("%s: %w", file, err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("%s names %s, which is empty", file, path)
	}
	return secret, nil
}

// loadBackend is the module SIGNARI_PKCS11_MODULE names, or the transit engine
// SIGNARI_VAULT_ADDR names, or nil when neither is set. Both set is refused:
// new keys are made in one place, and nothing would say which.
func loadBackend(getenv func(string) string) (Backend, error) {
	module, vault := getenv("SIGNARI_PKCS11_MODULE"), getenv("SIGNARI_VAULT_ADDR")
	switch {
	case module != "" && vault != "":
		return nil, fmt.Errorf("SIGNARI_PKCS11_MODULE and SIGNARI_VAULT_ADDR are both set; new signing " +
			"keys are made in one place, so set one")
	case vault != "":
		return loadVault(getenv, vault)
	case module == "":
		return nil, nil
	}
	// The token is named rather than taken as the first one found, so a module
	// with a second token cannot have keys made in the wrong one.
	token := getenv("SIGNARI_PKCS11_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("SIGNARI_PKCS11_MODULE is set and SIGNARI_PKCS11_TOKEN is not; " +
			"name the token, by its label, that holds the signing keys")
	}
	pin, path := getenv("SIGNARI_PKCS11_PIN"), getenv("SIGNARI_PKCS11_PIN_FILE")
	switch {
	case pin != "" && path != "":
		return nil, fmt.Errorf("SIGNARI_PKCS11_PIN and SIGNARI_PKCS11_PIN_FILE are both set; set one")
	case path != "":
		var err error
		if pin, err = secretFile("SIGNARI_PKCS11_PIN_FILE", path, "The PIN signs as this deployment"); err != nil {
			return nil, err
		}
	case pin == "":
		return nil, fmt.Errorf("SIGNARI_PKCS11_MODULE is set and neither SIGNARI_PKCS11_PIN nor " +
			"SIGNARI_PKCS11_PIN_FILE is; the token's user PIN is needed to sign")
	}
	return newPKCS11(module, token, pin)
}

// loadVault reads the transit engine's settings. A token file is read again
// for every request, so a token Vault Agent renews into it goes on working;
// it is read once here too, so a missing or loose one stops the process now
// rather than at the first signature.
func loadVault(getenv func(string) string, addr string) (Backend, error) {
	value, path := getenv("SIGNARI_VAULT_TOKEN"), getenv("SIGNARI_VAULT_TOKEN_FILE")
	var token func() (string, error)
	switch {
	case value != "" && path != "":
		return nil, fmt.Errorf("SIGNARI_VAULT_TOKEN and SIGNARI_VAULT_TOKEN_FILE are both set; set one")
	case path != "":
		token = func() (string, error) {
			return secretFile("SIGNARI_VAULT_TOKEN_FILE", path, "The token signs as this deployment")
		}
		if _, err := token(); err != nil {
			return nil, err
		}
	case value != "":
		token = func() (string, error) { return value, nil }
	default:
		return nil, fmt.Errorf("SIGNARI_VAULT_ADDR is set and neither SIGNARI_VAULT_TOKEN nor " +
			"SIGNARI_VAULT_TOKEN_FILE is; a token allowed to sign with the transit keys is needed")
	}
	return newVault(addr, getenv("SIGNARI_VAULT_TRANSIT_MOUNT"), token)
}
