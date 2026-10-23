package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Each command parses its own flags (6.15). run() defines every flag once, on
// one FlagSet that is the registry, and a command's FlagSet holds the ones its
// branch of the dispatch reads (commandFlags, derived from that dispatch) and
// the ones every command does, sharing their values. Before, the registry was
// the parser, so a flag a command ignores was accepted without a word and -h
// listed all of them.

// commonFlags are parsed by every command: where the database is, and how
// long a command may run.
var commonFlags = []string{"dsn", "timeout"}

// beforeFlags are the commands run() answers before any command's flags are
// parsed, which take words rather than flags: `signari help keys rotate`,
// `signari completion zsh`.
var beforeFlags = []string{"help", "completion"}

// bookkeepingFlags are read for every command without changing what one does,
// each with the reason; a command parses one only when its branch reads it too.
var bookkeepingFlags = map[string]string{
	"org": "named in the audit record every command that changed something writes",
}

// usageError is a command used wrongly: unknown, given a flag it does not
// take, or missing one it needs. It exits 2, as a failure exits 1.
type usageError struct{ error }

func (u usageError) Unwrap() error { return u.error }

// errDrift is `signari plan` finding the deployment differs from the file,
// which exits 3 so a pipeline can tell drift from failure.
var errDrift = errors.New("the deployment differs from the file")

// asksForAFlag matches the messages commands answer a missing or wrong flag
// with, the wording the flag-message guards read: "give -org", "idp link
// needs -slug", "-offer-expires must be".
var asksForAFlag = regexp.MustCompile(`^(give -|[a-z][a-z0-9-]*( [a-z][a-z0-9-]*)? needs -|-[a-z][a-z0-9-]* (is required|must) )`)

// exitCode is what the process exits with for err: 2 for usage, 3 for drift,
// 1 for anything else.
func exitCode(err error) int {
	var u usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &u), asksForAFlag.MatchString(err.Error()):
		return 2
	case errors.Is(err, errDrift):
		return 3
	}
	return 1
}

// commandFlagSet is cmd's own FlagSet over the registry's values.
func commandFlagSet(registry *flag.FlagSet, cmd string) (*flag.FlagSet, error) {
	names, ok := commandFlags[cmd]
	if !ok {
		group, _, _ := strings.Cut(cmd, " ")
		if verbs := groupVerbs(group); len(verbs) > 0 {
			return nil, usageError{fmt.Errorf("%q is not a command; `signari %s` takes %s", cmd, group,
				strings.Join(verbs, ", "))}
		}
		return nil, usageError{fmt.Errorf("%q is not a command; `signari help` lists them", cmd)}
	}
	fs := flag.NewFlagSet("signari "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, n := range slices.Concat(commonFlags, names) {
		if fs.Lookup(n) != nil {
			continue
		}
		f := registry.Lookup(n)
		if f == nil {
			return nil, fmt.Errorf("commandFlags gives %q the flag -%s, which run() does not define", cmd, n)
		}
		fs.Var(f.Value, f.Name, f.Usage)
	}
	return fs, nil
}

// groupVerbs are the second words of a two-word command group, sorted.
func groupVerbs(group string) []string {
	var verbs []string
	for c := range commandFlags {
		if g, verb, ok := strings.Cut(c, " "); ok && g == group {
			verbs = append(verbs, verb)
		}
	}
	sort.Strings(verbs)
	return verbs
}

// commandSummaries are the one-line descriptions usage() gives, by command.
func commandSummaries() map[string]string {
	out := map[string]string{}
	line := regexp.MustCompile(`^  ([a-z0-9-]+(?: [a-z0-9-]+)?)\s{2,}(\S.*)$`)
	more := regexp.MustCompile(`^\s{8,}(\S.*)$`)
	last := ""
	for _, l := range strings.Split(usageText, "\n") {
		if m := line.FindStringSubmatch(l); m != nil {
			if _, ok := commandFlags[m[1]]; ok {
				out[m[1]], last = m[2], m[1]
				continue
			}
		}
		if m := more.FindStringSubmatch(l); m != nil && last != "" {
			out[last] += " " + m[1]
			continue
		}
		last = ""
	}
	return out
}

// printCommandHelp is `signari help <command>` and `signari <command> -h`:
// what the command does and the flags it takes, no others.
func printCommandHelp(w io.Writer, cmd string, fs *flag.FlagSet) {
	fmt.Fprintf(w, "usage: signari %s [flags]\n", cmd)
	if s := commandSummaries()[cmd]; s != "" {
		fmt.Fprintf(w, "\n  %s\n", s)
	}
	fmt.Fprintf(w, "\nflags:\n")
	printFlags(w, fs)
	fmt.Fprintf(w, "\ndocs/cli.md describes every command.\n")
}

// printFlags is PrintDefaults without its reading of a backquoted word as the
// argument's name: the usage strings were written for one FlagSet serving
// every command, and quote command names (`keys rotate`), which it printed as
// `-alg keys rotate`.
func printFlags(w io.Writer, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		plain := *f
		plain.Usage = strings.ReplaceAll(f.Usage, "`", "")
		kind, usage := flag.UnquoteUsage(&plain)
		fmt.Fprintf(w, "  -%s", f.Name)
		if kind != "" {
			fmt.Fprintf(w, " %s", kind)
		}
		fmt.Fprintf(w, "\n    \t%s", strings.ReplaceAll(usage, "\n", "\n    \t"))
		switch f.DefValue {
		case "", "0", "false", "0s":
		default:
			if kind == "string" {
				fmt.Fprintf(w, " (default %q)", f.DefValue)
			} else {
				fmt.Fprintf(w, " (default %s)", f.DefValue)
			}
		}
		fmt.Fprintln(w)
	})
}

// commandHelp answers `signari help`, `signari help <group>` and `signari
// help <command>`.
func commandHelp(w io.Writer, registry *flag.FlagSet, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(w, usageText)
		return nil
	}
	cmd := strings.Join(args, " ")
	if _, ok := commandFlags[cmd]; !ok {
		if verbs := groupVerbs(cmd); len(verbs) > 0 {
			fmt.Fprintf(w, "signari %s takes:\n", cmd)
			summaries := commandSummaries()
			for _, v := range verbs {
				fmt.Fprintln(w, strings.TrimRight(fmt.Sprintf("  %-28s %s", cmd+" "+v, summaries[cmd+" "+v]), " "))
			}
			return nil
		}
	}
	fs, err := commandFlagSet(registry, cmd)
	if err != nil {
		return err
	}
	printCommandHelp(w, cmd, fs)
	return nil
}

// printCompletion writes a completion script for bash, or for zsh through its
// bash compatibility, from the command table: the commands, the verbs of each
// group, and each command's flags.
func printCompletion(w io.Writer, args []string) error {
	if len(args) != 1 || (args[0] != "bash" && args[0] != "zsh") {
		return usageError{errors.New("give the shell: `signari completion bash` or `signari completion zsh`")}
	}
	if args[0] == "zsh" {
		fmt.Fprintln(w, "autoload -U +X bashcompinit && bashcompinit")
	}
	firsts := map[string]bool{"help": true, "completion": true}
	groups := map[string][]string{}
	cmds := make([]string, 0, len(commandFlags))
	for c := range commandFlags {
		cmds = append(cmds, c)
		g, verb, two := strings.Cut(c, " ")
		firsts[g] = true
		if two {
			groups[g] = append(groups[g], verb)
		}
	}
	sort.Strings(cmds)
	words := make([]string, 0, len(firsts))
	for f := range firsts {
		words = append(words, f)
	}
	sort.Strings(words)
	fmt.Fprintln(w, "_signari() {")
	fmt.Fprintln(w, `  local cur=${COMP_WORDS[COMP_CWORD]} first=${COMP_WORDS[1]} cmd flags=""`)
	fmt.Fprintf(w, "  if [[ $COMP_CWORD -eq 1 ]]; then COMPREPLY=($(compgen -W %q -- \"$cur\")); return; fi\n",
		strings.Join(words, " "))
	fmt.Fprintln(w, `  case "$first" in`)
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		sort.Strings(groups[g])
		fmt.Fprintf(w, "    %s) if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=($(compgen -W %q -- \"$cur\")); return; fi\n",
			g, strings.Join(groups[g], " "))
		fmt.Fprintln(w, `      cmd="$first ${COMP_WORDS[2]}" ;;`)
	}
	fmt.Fprintln(w, `    *) cmd="$first" ;;`)
	fmt.Fprintln(w, "  esac")
	fmt.Fprintln(w, `  case "$cmd" in`)
	for _, c := range cmds {
		flags := make([]string, 0, len(commonFlags)+len(commandFlags[c]))
		for _, f := range slices.Concat(commonFlags, commandFlags[c]) {
			flags = append(flags, "-"+f)
		}
		fmt.Fprintf(w, "    %q) flags=%q ;;\n", c, strings.Join(flags, " "))
	}
	fmt.Fprintln(w, "  esac")
	fmt.Fprintln(w, `  COMPREPLY=($(compgen -W "$flags" -- "$cur"))`)
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w, "complete -F _signari signari")
	return nil
}
