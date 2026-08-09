// Package migrations embeds the SQL migration set into the binary.
//
// Shipping every intermediate migration inside the image is what makes
// "refuse version skips, then perform them yourself" possible: `idp migrate up`
// from version 1 to 5 walks 1→2→3→4→5 internally rather than telling the
// operator not to skip. Documentation is not a mechanism.
package migrations

import "embed"

//go:embed core/*.sql
var FS embed.FS
