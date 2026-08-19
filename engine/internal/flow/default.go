package flow

import (
	_ "embed"
	"fmt"
	"sync"
)

//go:embed default.yaml
var defaultDoc []byte

var (
	defaultOnce sync.Once
	defaultFile *File
	defaultErr  error
)

// Default returns the built-in flows.
//
// Parsed on first use rather than in an init function, and returning an error
// rather than panicking. A panic during package initialisation is an outage with
// no message an operator can act on, and this file is embedded -- if it is
// broken, every binary is broken, so the failure needs to arrive somewhere it
// can be printed.
//
// In practice it cannot be broken in a released binary: TestTheDefaultFlowsLoad
// parses it, which means the safety analysis and the file's own test cases both
// run in CI. That is the property worth having -- the default journey is held to
// exactly the rules an operator's own file is held to, rather than being trusted
// because it came with the software.
func Default() (*File, error) {
	defaultOnce.Do(func() {
		defaultFile, defaultErr = Parse(defaultDoc)
		if defaultErr != nil {
			defaultErr = fmt.Errorf("the built-in flows did not load: %w", defaultErr)
		}
	})
	return defaultFile, defaultErr
}

// DefaultDocument returns the built-in file verbatim, for an operator who wants
// to start from it. `signari flow show --default` prints this.
func DefaultDocument() []byte {
	out := make([]byte, len(defaultDoc))
	copy(out, defaultDoc)
	return out
}
