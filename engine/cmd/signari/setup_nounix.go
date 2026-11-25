//go:build !unix

package main

// dirOwner answers nothing where files have no owning uid to give.
func dirOwner(string) (uid, gid int, ok bool) { return 0, 0, false }
