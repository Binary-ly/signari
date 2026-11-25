package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// How `signari setup` asks. Only at a terminal: stdin and stdout both, CI
// unset, and none of -yes, -json, -dry-run or -check given. Anywhere else it
// asks nothing, takes the default an answer has, and names the flag for one
// that has none.

// errCancelled is the person at the terminal ending setup before it began.
var errCancelled = errors.New("cancelled at the prompt; nothing was changed")

// prompter asks the person at the terminal. Labels and hints are kept to 74
// characters, which an 80-column terminal shows whole with the indent.
type prompter interface {
	// ask shows label and hint and returns what was typed, or def for an
	// empty line, asking again for as long as valid refuses it.
	ask(label, hint, def string, valid func(string) error) (string, error)
	// confirm is a yes or no, def for an empty line.
	confirm(label, hint string, def bool) (bool, error)
	// secret reads a line without echoing it.
	secret(label, hint string) (string, error)
}

// ciSet says whether this runs under continuous integration, which sets CI;
// "0" and "false" say it does not.
func ciSet(getenv func(string) string) bool {
	switch strings.ToLower(strings.TrimSpace(getenv("CI"))) {
	case "", "0", "false":
		return false
	}
	return true
}

// atTerminal says whether stdin and stdout are both terminals.
func atTerminal() bool {
	return term.IsTerminal(fdOf(os.Stdin)) && term.IsTerminal(fdOf(os.Stdout))
}

func fdOf(f *os.File) int {
	return int(f.Fd()) // #nosec G115 -- a descriptor number, which the kernel keeps small
}

// termPrompter asks on this process's terminal.
type termPrompter struct {
	in  *bufio.Reader
	fd  int
	out io.Writer
}

func newTermPrompter(out io.Writer) *termPrompter {
	return &termPrompter{in: bufio.NewReader(os.Stdin), fd: fdOf(os.Stdin), out: out}
}

func (p *termPrompter) line() (string, error) {
	s, err := p.in.ReadString('\n')
	if errors.Is(err, io.EOF) && s == "" {
		fmt.Fprintln(p.out)
		return "", errCancelled
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (p *termPrompter) ask(label, hint, def string, valid func(string) error) (string, error) {
	fmt.Fprintf(p.out, "\n? %s\n  %s\n", label, hint)
	for {
		if def != "" {
			fmt.Fprintf(p.out, "  [%s] > ", def)
		} else {
			fmt.Fprint(p.out, "  > ")
		}
		s, err := p.line()
		if err != nil {
			return "", err
		}
		if s == "" {
			s = def
		}
		if err := valid(s); err != nil {
			fmt.Fprintf(p.out, "  ! %v\n", err)
			continue
		}
		return s, nil
	}
}

func (p *termPrompter) confirm(label, hint string, def bool) (bool, error) {
	choice := "[Y/n]"
	if !def {
		choice = "[y/N]"
	}
	fmt.Fprintf(p.out, "\n? %s\n  %s\n", label, hint)
	for {
		fmt.Fprintf(p.out, "  %s > ", choice)
		s, err := p.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "  ! answer y or n")
	}
}

// secret reads without echo. An interrupt while it waits puts the terminal
// back as it was before ending the process, which would otherwise leave it not
// echoing what is typed next.
func (p *termPrompter) secret(label, hint string) (string, error) {
	fmt.Fprintf(p.out, "\n? %s\n  %s\n  > ", label, hint)
	if state, err := term.GetState(p.fd); err == nil {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			select {
			case <-sig:
				_ = term.Restore(p.fd, state)
				fmt.Fprintln(p.out)
				os.Exit(130)
			case <-done:
			}
		}()
		defer func() {
			signal.Stop(sig)
			close(done)
		}()
	}
	b, err := term.ReadPassword(p.fd)
	fmt.Fprintln(p.out)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
