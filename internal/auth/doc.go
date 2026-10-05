// Package auth verifies owner-bearer tokens and Cloudflare Access assertions.
//
// The API never treats an opaque client bearer as identity in Access mode.
// Secrets, assertions, and minted tokens must not appear in logs or dashboard
// responses. Implementation lands in a later task; this package currently
// holds the boundary types.
package auth

// Principal is a verified operator identity.
type Principal struct {
	Issuer  string
	Subject string
}

// Mode is the mutually exclusive public authentication mode.
type Mode string

const (
	ModeOwnerBearer      Mode = "owner-bearer"
	ModeCloudflareAccess Mode = "cloudflare-access"
)
