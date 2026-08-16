// Package rac speaks the Guacamole protocol to guacd, for remote desktop and
// shell access through a browser.
//
// # What this is and is not
//
// guacd is the daemon that actually speaks RDP, VNC and SSH. It is a mature C
// program that has been doing this for over a decade, and reimplementing it
// would be a project rather than a feature -- so this WRAPS it, exactly as the
// roadmap says.
//
// What this package provides is the half guacd does not: deciding whether the
// person asking may reach the host they asked for. guacd itself has no notion
// of a user; it connects to whatever it is told to connect to. Everything that
// makes remote access safe -- who you are, whether policy allows it, what gets
// recorded -- lives here.
//
// # The protocol
//
// Text, and small enough to implement rather than depend on:
//
//	LENGTH.VALUE,LENGTH.VALUE,...;
//
// The length is in CHARACTERS, not bytes, which matters the moment a hostname
// or a username is not ASCII: counting bytes there produces a stream guacd
// reads as truncated and abandons, and the symptom is a connection that dies
// during the handshake with nothing useful logged.
//
// # No Docker socket
//
// The roadmap is explicit and it is worth repeating: this connects to guacd
// over TCP. It does not talk to a container runtime, does not start containers,
// and does not need a mounted Docker socket -- which is root on the host,
// handed to a service that accepts connections from browsers.
package rac

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxInstructionRunes bounds one instruction.
//
// The protocol has no limit of its own, so a hostile or broken peer can declare
// an arbitrarily long element and make the reader allocate it. guacd's own
// instructions are small; a megabyte is far beyond anything legitimate and far
// below anything dangerous.
const maxInstructionRunes = 1 << 20

// Instruction is one protocol message: an opcode and its arguments.
type Instruction struct {
	Opcode string
	Args   []string
}

// String renders an instruction in wire form.
//
// Lengths are counted in RUNES. This is the single most common way to get this
// protocol wrong: len() on a Go string is bytes, and any non-ASCII character in
// a username, hostname or window title then declares a length guacd reads past
// the end of.
func (i Instruction) String() string {
	var b strings.Builder
	write := func(s string) {
		b.WriteString(strconv.Itoa(utf8.RuneCountInString(s)))
		b.WriteByte('.')
		b.WriteString(s)
	}
	write(i.Opcode)
	for _, a := range i.Args {
		b.WriteByte(',')
		write(a)
	}
	b.WriteByte(';')
	return b.String()
}

// Reader decodes instructions from a stream.
type Reader struct {
	br *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 16<<10)}
}

// ReadInstruction reads one complete instruction.
//
// Returns io.EOF only at a clean boundary. A stream that ends part-way through
// an instruction is an ERROR rather than an EOF: treating a truncated read as a
// clean end is how a proxy silently drops the last thing somebody typed.
func (r *Reader) ReadInstruction() (Instruction, error) {
	var inst Instruction
	first := true

	for {
		length, err := r.readLength(first)
		if err != nil {
			return inst, err
		}
		first = false

		value, err := r.readRunes(length)
		if err != nil {
			return inst, err
		}
		if inst.Opcode == "" && len(inst.Args) == 0 {
			inst.Opcode = value
		} else {
			inst.Args = append(inst.Args, value)
		}

		sep, err := r.br.ReadByte()
		if err != nil {
			return inst, fmt.Errorf("truncated instruction after %q: %w", value, err)
		}
		switch sep {
		case ';':
			return inst, nil
		case ',':
			continue
		default:
			return inst, fmt.Errorf("expected ',' or ';' after an element, got %q", sep)
		}
	}
}

// readLength reads the decimal length and the dot after it.
func (r *Reader) readLength(atStart bool) (int, error) {
	var digits []byte
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			if err == io.EOF && atStart && len(digits) == 0 {
				// A clean end: nothing had been read of this instruction.
				return 0, io.EOF
			}
			return 0, fmt.Errorf("reading an element length: %w", err)
		}
		if b == '.' {
			break
		}
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("expected a digit in an element length, got %q", b)
		}
		digits = append(digits, b)
		if len(digits) > 8 {
			return 0, fmt.Errorf("element length is absurd")
		}
	}
	if len(digits) == 0 {
		return 0, fmt.Errorf("element with no length")
	}
	n, err := strconv.Atoi(string(digits))
	if err != nil {
		return 0, err
	}
	if n > maxInstructionRunes {
		return 0, fmt.Errorf("element declares %d characters, over the %d limit",
			n, maxInstructionRunes)
	}
	return n, nil
}

// readRunes reads exactly n runes.
//
// Runes, not bytes, because that is what the length means. Reading n bytes
// instead works perfectly until somebody's hostname has an accent in it.
func (r *Reader) readRunes(n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		ru, _, err := r.br.ReadRune()
		if err != nil {
			return "", fmt.Errorf("reading element content: %w", err)
		}
		b.WriteRune(ru)
	}
	return b.String(), nil
}

// Writer encodes instructions to a stream.
type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (w *Writer) Write(i Instruction) error {
	_, err := io.WriteString(w.w, i.String())
	return err
}
