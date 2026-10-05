// Package sandbox encodes Docker executor policy for Cloud Harness.
//
// This is not GoClaw's sandbox defaults. Cloud Harness executors are non-root,
// read-only rootfs, dropped capabilities, no-new-privileges, TTL-limited, with
// one writable repository mount and no Docker socket. Network profiles are
// only network-none and dependency-access; attestation failure is fail-closed
// (DEPENDENCY_EGRESS_UNAVAILABLE) and never a silent downgrade.
package sandbox

import "github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

// DefaultNetworkProfile is the shipped executor egress default.
const DefaultNetworkProfile = protocol.DependencyAccess
