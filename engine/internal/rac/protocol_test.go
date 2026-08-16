package rac

import (
	"io"
	"strings"
	"testing"
)

// The protocol layer. Small enough to implement, and with exactly one trap.

func TestInstructionEncoding(t *testing.T) {
	cases := []struct {
		in   Instruction
		want string
	}{
		{Instruction{Opcode: "select", Args: []string{"rdp"}}, "6.select,3.rdp;"},
		{Instruction{Opcode: "size", Args: []string{"1024", "768", "96"}},
			"4.size,4.1024,3.768,2.96;"},
		{Instruction{Opcode: "audio"}, "5.audio;"},
		{Instruction{Opcode: "connect", Args: []string{"", "host"}},
			"7.connect,0.,4.host;"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("encoded %q, want %q", got, c.want)
		}
	}
}

// TestLengthsAreRunesNotBytes is the trap.
//
// len() on a Go string is bytes. Any non-ASCII character in a hostname,
// username or window title then declares a length guacd reads past the end of,
// and the connection dies mid-handshake with nothing useful logged.
func TestLengthsAreRunesNotBytes(t *testing.T) {
	// "café" is 4 characters and 5 bytes; "日本" is 2 characters and 6.
	got := Instruction{Opcode: "connect", Args: []string{"café", "日本"}}.String()
	want := "7.connect,4.café,2.日本;"
	if got != want {
		t.Fatalf("encoded %q\n    want %q\n\nLengths must be in characters. "+
			"Counting bytes produces a stream guacd reads as truncated.", got, want)
	}

	// And it round-trips.
	in, err := NewReader(strings.NewReader(got)).ReadInstruction()
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Args) != 2 || in.Args[0] != "café" || in.Args[1] != "日本" {
		t.Fatalf("round-tripped to %+v", in)
	}
}

func TestReadInstruction(t *testing.T) {
	r := NewReader(strings.NewReader("4.args,8.hostname,4.port;5.ready,4.$abc;"))

	first, err := r.ReadInstruction()
	if err != nil {
		t.Fatal(err)
	}
	if first.Opcode != "args" || len(first.Args) != 2 || first.Args[0] != "hostname" {
		t.Fatalf("first instruction is %+v", first)
	}

	second, err := r.ReadInstruction()
	if err != nil {
		t.Fatal(err)
	}
	if second.Opcode != "ready" || second.Args[0] != "$abc" {
		t.Fatalf("second instruction is %+v", second)
	}

	if _, err := r.ReadInstruction(); err != io.EOF {
		t.Fatalf("expected a clean EOF at the boundary, got %v", err)
	}
}

// TestTruncatedStreamIsAnErrorNotAnEOF: a stream that stops mid-instruction has
// lost data, and reporting it as a clean end drops whatever was being sent.
func TestTruncatedStreamIsAnErrorNotAnEOF(t *testing.T) {
	for _, partial := range []string{
		"4.args,8.hostn",    // cut inside a value
		"4.args,8.hostname", // no terminator
		"4.arg",             // cut inside the opcode
		"4.",                // length with no value
	} {
		r := NewReader(strings.NewReader(partial))
		_, err := r.ReadInstruction()
		if err == nil {
			t.Errorf("%q was accepted as a complete instruction", partial)
			continue
		}
		if err == io.EOF {
			t.Errorf("%q reported a clean EOF; it is a truncated instruction and "+
				"treating it as an ending silently drops data", partial)
		}
	}
}

func TestMalformedInstructionsAreRefused(t *testing.T) {
	bad := []string{
		"x.select;",          // length is not a number
		"4.args:8.hostname;", // wrong separator
		"999999999.a;",       // absurd length
		".select;",           // no length
	}
	for _, s := range bad {
		if _, err := NewReader(strings.NewReader(s)).ReadInstruction(); err == nil {
			t.Errorf("%q was accepted", s)
		}
	}
}

// TestOversizedElementIsRefused: the protocol has no length limit of its own,
// so a hostile peer can otherwise make the reader allocate whatever it likes.
func TestOversizedElementIsRefused(t *testing.T) {
	_, err := NewReader(strings.NewReader("2000000.a;")).ReadInstruction()
	if err == nil {
		t.Fatal("an element declaring two million characters was accepted")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
