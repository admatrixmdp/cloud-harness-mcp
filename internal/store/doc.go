// Package store is the SQLite metadata layer (today apps/runner metadata/state stores).
//
// Follow GoClaw store style: database/sql, modernc.org/sqlite, no ORM, raw SQL
// with positional parameters. Interfaces live here; implementations may split
// later without changing the runner RPC contract.
package store
