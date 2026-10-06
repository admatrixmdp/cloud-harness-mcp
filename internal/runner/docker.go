package runner

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
)

// DockerEngine adapts sandbox.Engine to the workspace Engine interface.
type DockerEngine struct {
	Inner    *sandbox.Engine
	JobsRoot string
}

func containerName(id string) string {
	if len(id) < 19 {
		id = id + strings.Repeat("x", 19-len(id))
	}
	return "cloud-harness-ws-" + strings.ToLower(id[3:19])
}

// Create runs docker create with Cloud Harness executor policy.
// The job repo is bind-mounted at /workspace. The Docker socket is never mounted.
func (d DockerEngine) Create(ctx context.Context, rec store.Record) (string, error) {
	name := containerName(rec.ID)
	spec := sandbox.ExecutorSpec{
		Name:        name,
		WorkspaceID: rec.ID,
		InstanceID:  d.Inner.InstanceID,
		Network:     rec.NetworkProfile,
		Image:       d.Inner.Image,
	}
	if d.JobsRoot != "" && rec.ID != "" {
		spec.RepositoryPath = filepath.Join(d.JobsRoot, rec.ID, "repo")
	}
	return d.Inner.CreateExecutor(ctx, spec)
}

// Remove force-removes the managed container.
func (d DockerEngine) Remove(ctx context.Context, name string) error {
	return d.Inner.RemoveExecutor(ctx, name)
}
