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
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%s names %s, which its group or others may read (mode %04o); "+
				"make it 0400 or 0600 for the user this runs as. The root key opens every "+
				"signing key", file, path, perm)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- the operator names the file
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if b64 = strings.TrimSpace(string(data)); b64 == "" {
			return nil, fmt.Errorf("%s names %s, which is empty", file, path)
		}
	case b64 == "":
		return nil, fmt.Errorf("%s is unset (32 random bytes, base64), and so is %s -- generate one with:\n"+
			"  head -c 32 /dev/urandom | base64", value, file)
	}
	return NewRootKeyFromBase64(getenv(ref), b64)
}
