// Package protocol is the public wire contract for Cloud Harness MCP.
//
// Types and JSON field names must stay compatible with packages/contracts
// (Zod schemas in TypeScript). Downstream Go packages consume this package
// instead of inventing a second envelope.
package protocol
