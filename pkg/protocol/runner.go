package protocol

import "encoding/json"

// RunnerRequest is the versioned API→runner RPC envelope (RunnerRequestSchema).
type RunnerRequest struct {
	Version   int             `json:"version"`
	OwnerID   string          `json:"ownerId,omitempty"`
	Principal json.RawMessage `json:"principal,omitempty"`
	Operation Operation       `json:"operation"`
	Input     json.RawMessage `json:"input"`
}

// PrincipalKind is the runner principal discriminator.
type PrincipalKind string

const (
	PrincipalOwner    PrincipalKind = "owner"
	PrincipalExternal PrincipalKind = "external"
)

// OwnerPrincipal is RunnerPrincipalSelector kind=owner.
type OwnerPrincipal struct {
	Kind    PrincipalKind `json:"kind"`
	OwnerID string        `json:"ownerId"`
}

// ExternalPrincipal is an Access-normalized identity. Email/name are metadata.
type ExternalPrincipal struct {
	Kind    PrincipalKind `json:"kind"`
	Issuer  string        `json:"issuer"`
	Subject string        `json:"subject"`
	Email   string        `json:"email,omitempty"`
	Name    string        `json:"name,omitempty"`
}

// RepositoryCapabilities is the GitHub-facing grant summary.
type RepositoryCapabilities struct {
	Read               bool `json:"read"`
	Push               bool `json:"push"`
	IssuesRead         bool `json:"issuesRead"`
	IssuesWrite        bool `json:"issuesWrite"`
	PullRequestsRead   bool `json:"pullRequestsRead"`
	PullRequestsWrite  bool `json:"pullRequestsWrite"`
}

// WorkspaceNetworkExposure includes the local-stdio host profile.
type WorkspaceNetworkExposure string

const (
	ExposureNetworkNone      WorkspaceNetworkExposure = "network-none"
	ExposureDependencyAccess WorkspaceNetworkExposure = "dependency-access"
	ExposureLocalHost        WorkspaceNetworkExposure = "local-host"
)

// Valid reports whether e is a documented workspace network exposure.
func (e WorkspaceNetworkExposure) Valid() bool {
	switch e {
	case ExposureNetworkNone, ExposureDependencyAccess, ExposureLocalHost:
		return true
	default:
		return false
	}
}
