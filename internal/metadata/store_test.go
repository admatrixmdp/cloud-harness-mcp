package metadata

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestProjectEnvironmentLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "meta.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := int64(1_700_000_000_000)
	project, err := store.CreateProject("owner", "Harness", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixProject, project.ID) || project.Generation != 1 || project.State != "ACTIVE" {
		t.Fatalf("%+v", project)
	}
	if _, err := store.CreateProject("owner", "Harness", 0, now); err != ErrConflict {
		t.Fatalf("duplicate name %v", err)
	}
	renamed, err := store.UpdateProject("owner", project.ID, "Renamed", 1, now+1)
	if err != nil || renamed.Name != "Renamed" || renamed.Generation != 2 {
		t.Fatalf("%+v %v", renamed, err)
	}
	env, err := store.CreateEnvironment("owner", project.ID, "prod", 0, now+2)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, env.ID) || env.ProjectID != project.ID {
		t.Fatalf("%+v", env)
	}
	listed, err := store.ListEnvironments("owner", project.ID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v %+v", err, listed)
	}
	if _, err := store.DeleteProject("other", project.ID, 2, now+3); err != ErrConflict {
		t.Fatalf("cross-principal %v", err)
	}
	deleted, err := store.DeleteProject("owner", project.ID, 2, now+3)
	if err != nil || deleted.State != "DELETED" || deleted.Generation != 3 {
		t.Fatalf("%+v %v", deleted, err)
	}
	projects, err := store.ListProjects("owner")
	if err != nil || len(projects) != 0 {
		t.Fatalf("%v %+v", err, projects)
	}
}
