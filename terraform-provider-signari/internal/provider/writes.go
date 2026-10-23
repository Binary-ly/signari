package provider

import "sync"

// writeChain is the run of configuration versions this provider's own writes
// produced in this apply (0.45).
//
// The configuration version is the whole deployment's: every write anywhere
// bumps it, by one (the Admin API's mutateIf, engine/internal/adminapi/
// server.go). Each resource records the version its last read saw, and an
// update used to send exactly that. So in any apply that wrote twice, the
// second write was refused with 412: the first had moved the version past
// what the plan read, and the conflict reported was the apply's own.
//
// The fix keeps the guarantee and drops the false alarm. Writes go one at a
// time, and the provider remembers the versions (base, head] its own writes
// made. A resource read at a version from which every later bump was this
// apply's own is up to date, and its write is sent If-Match head. Anything
// else -- a write by a colleague, a pipeline or the console, before the apply
// or during it -- leaves a version the chain does not cover, and the write is
// sent the version the resource was read at, and refused, as before.
type writeChain struct {
	mu         sync.Mutex
	base, head int64
}

// write sends one write. read is the version the resource was last read at,
// 0 for a create, which has none and stays unconditional. send makes the
// request with the If-Match it is given and answers the version the server
// reports the write produced.
func (d *providerData) write(read int64, send func(ifMatch int64) (int64, error)) error {
	if !d.conditional {
		_, err := send(0)
		return err
	}
	c := &d.chain
	c.mu.Lock()
	defer c.mu.Unlock()

	ifMatch := read
	if read > 0 && c.head > 0 && read >= c.base && read <= c.head {
		ifMatch = c.head
	}
	now, err := send(ifMatch)
	if err != nil || now == 0 {
		return err
	}
	// An unconditional write held no precondition: what it covers is the
	// one bump it made.
	sent := ifMatch
	if sent == 0 {
		sent = now - 1
	}
	if c.head > 0 && sent == c.head {
		c.head = now
	} else {
		c.base, c.head = sent, now
	}
	return nil
}
