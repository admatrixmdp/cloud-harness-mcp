// Package secrets is the operator keyring and secret-metadata store.
//
// Plaintext values must never be logged, written to checkouts, echoed in MCP
// results, or returned by the dashboard BFF. Ciphertext stays on the runner.
package secrets
