//go:build unix

package main

import (
	"os"
	"syscall"
)

// dirOwner is the user and group that own dir, which a file setup makes there
// as root is given (setupfiles.go).
func dirOwner(dir string) (uid, gid int, ok bool) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true // #nosec G115 -- no system hands out a uid or gid above 2^31
}
