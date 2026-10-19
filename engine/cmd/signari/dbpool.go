package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// connectDB opens the one connection every command starts with.
//
// The DSN is parsed as the pool parses it, which takes the `pool_*` settings
// out before anything reaches the server. pgx.Connect sent them as run-time
// parameters, and PostgreSQL refuses a parameter it does not know, so a DSN
// carrying `pool_max_conns` -- the only way pgx offers to size the pool --
// failed the first connect of every command, `serve` included.
func connectDB(ctx context.Context, dsn string) (*pgx.Conn, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg.ConnConfig)
}

// openPool opens the connection pool on the same database as conn, sized by
// the DSN's `pool_*` settings and then the SIGNARI_DB_* variables.
func openPool(ctx context.Context, conn *pgx.Conn) (*pgxpool.Pool, error) {
	cfg, err := poolConfig(conn.Config().ConnString(), os.Getenv)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// poolConfig reads the pool's size and connection ages.
//
// A variable set wins over the DSN, because it is the control this page
// documents and the one an operator sets per deployment. A malformed value
// refuses to start: this is read at startup, where a typo that silently fell
// back to pgx's default of max(4, CPUs) would look like a pool that had been
// sized and was not, and would be found under load.
func poolConfig(dsn string, getenv func(string) string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if v := getenv("SIGNARI_DB_MAX_CONNS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("SIGNARI_DB_MAX_CONNS=%q: want a whole number of at least 1", v)
		}
		cfg.MaxConns = int32(n)
	}
	if v := getenv("SIGNARI_DB_MIN_CONNS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("SIGNARI_DB_MIN_CONNS=%q: want a whole number of at least 0", v)
		}
		cfg.MinConns = int32(n)
	}
	if v := getenv("SIGNARI_DB_MAX_CONN_LIFETIME"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("SIGNARI_DB_MAX_CONN_LIFETIME=%q: want a positive duration such as 30m", v)
		}
		cfg.MaxConnLifetime = d
	}
	if v := getenv("SIGNARI_DB_MAX_CONN_IDLE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("SIGNARI_DB_MAX_CONN_IDLE=%q: want a positive duration such as 5m", v)
		}
		cfg.MaxConnIdleTime = d
	}
	// pgx keeps a minimum above the maximum without complaint and opens
	// connections toward it until the maximum stops it, so the pool the
	// operator asked for and the one they got would differ in silence.
	if cfg.MinConns > cfg.MaxConns {
		return nil, fmt.Errorf("the pool's minimum (%d connections) is above its maximum (%d)",
			cfg.MinConns, cfg.MaxConns)
	}
	return cfg, nil
}
