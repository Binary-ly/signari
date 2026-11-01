package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// sentQuerier keeps what a statement was given, and answers nothing.
type sentQuerier struct{ args []any }

func (s *sentQuerier) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	s.args = args
	return nil, errors.New("not asked")
}

// A batch names its subject once per question, and each mention would find all
// their relations again for DISTINCT to throw away (E.17). The lists sent are
// the distinct ones, by pair: a type and an id are one name between them.
func TestABatchNamesEachThingToTheDatabaseOnce(t *testing.T) {
	var subjects, objects [][2]string
	var relations []string
	for range 100 {
		subjects = append(subjects, [2]string{"user", "ann"}, [2]string{"user", "id-1"})
		objects = append(objects, [2]string{"doc", "a"}, [2]string{"folder", "a"})
		relations = append(relations, "owner", "editor")
	}
	sent := &sentQuerier{}
	if _, err := TuplesAmong(context.Background(), sent, "org", subjects, objects, relations); err == nil {
		t.Fatal("the stub answers an error")
	}
	if len(sent.args) != 6 {
		t.Fatalf("%d arguments", len(sent.args))
	}
	for i, want := range map[int]int{1: 2, 2: 2, 3: 2, 4: 2, 5: 2} {
		if got := len(sent.args[i].([]string)); got != want {
			t.Errorf("argument %d sent %d values, want %d: %v", i, got, want, sent.args[i])
		}
	}
	if types := sent.args[3].([]string); types[0] != "doc" || types[1] != "folder" {
		t.Errorf("two objects with one id were taken for one: %v", types)
	}
}
