package migrate

import (
	"context"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

// MinServerMajor is the oldest PostgreSQL this release runs on (3.28): the
// oldest it was tested on. An older major is refused rather than assumed to
// work, since no older one has been run against; nothing declared a range,
// so an older server found out part way through the migrations.
var MinServerMajor = 17

// TestedServerMajors are the majors this release's suites ran against. A
// newer one runs, and `signari doctor` says it was not tested here.
var TestedServerMajors = []int{17}

// ServerMajor is the PostgreSQL major version conn is connected to.
func ServerMajor(ctx context.Context, conn *pgx.Conn) (int, error) {
	var num int
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&num); err != nil {
		return 0, fmt.Errorf("reading the server version: %w", err)
	}
	return num / 10000, nil
}

// checkServer refuses a PostgreSQL older than MinServerMajor.
func checkServer(ctx context.Context, conn *pgx.Conn) error {
	major, err := ServerMajor(ctx, conn)
	if err != nil {
		return err
	}
	if major < MinServerMajor {
		return fmt.Errorf("PostgreSQL %d is older than %d, the oldest this release runs on "+
			"(it is tested on %v); upgrade the database first", major, MinServerMajor, TestedServerMajors)
	}
	return nil
}

// Tested reports whether a major is one this release's suites ran against.
func Tested(major int) bool { return slices.Contains(TestedServerMajors, major) }
