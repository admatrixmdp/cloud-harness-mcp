package auth

import "context"

type identityCtxKey struct{}

// RequestIdentity is the verified caller attached to an HTTP request.
// The raw Access JWT is never stored here.
type RequestIdentity struct {
	Mode      Mode
	OwnerID   string
	Issuer    string
	Subject   string
	Email     string
	Name      string
	ExpiresAt int64
}

// WithIdentity stores a verified identity on ctx.
func WithIdentity(ctx context.Context, id RequestIdentity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

// IdentityFrom returns the verified identity, if any.
func IdentityFrom(ctx context.Context) (RequestIdentity, bool) {
	id, ok := ctx.Value(identityCtxKey{}).(RequestIdentity)
	return id, ok
}
