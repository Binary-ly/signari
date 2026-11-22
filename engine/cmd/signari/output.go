package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// What a listing command prints with -o json (6.15): the rows its table shows,
// as an array of objects, for a script to read instead of the columns. The
// text is printed as it always was, so nothing that reads it changes.

// output is one command's choice of text or JSON.
type output struct {
	json bool
	w    io.Writer
	rows []any
}

// newOutput answers the output -o asks for, refusing a format there is none of.
func newOutput(format string) (*output, error) {
	switch format {
	case "", "text":
		return &output{w: os.Stdout}, nil
	case "json":
		return &output{json: true, w: os.Stdout}, nil
	}
	return nil, usageError{fmt.Errorf("-o is text or json, not %q", format)}
}

// add records one row for JSON; in text it does nothing, the caller having
// printed the row as it always has.
func (o *output) add(row any) {
	if o.json {
		o.rows = append(o.rows, row)
	}
}

// text reports whether the caller prints its text.
func (o *output) text() bool { return !o.json }

// flush prints the rows as JSON, an empty array for none.
func (o *output) flush() error {
	if !o.json {
		return nil
	}
	if o.rows == nil {
		o.rows = []any{}
	}
	enc := json.NewEncoder(o.w)
	enc.SetIndent("", "  ")
	return enc.Encode(o.rows)
}

// value prints one object as JSON, for a command that shows one thing.
func (o *output) value(v any) error {
	enc := json.NewEncoder(o.w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
