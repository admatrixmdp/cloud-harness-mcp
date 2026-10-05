// Package artifacts is the principal-owned retained snapshot store.
//
// Payload files live under a confined objects root. Metadata stays in SQLite.
// Local stdio does not host this store; the runner does.
package artifacts
