package skillsreg

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "skills.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCreateListArchiveAndSets(t *testing.T) {
	store := openStore(t)
	now := int64(1)
	created, err := store.CreateCustom("owner", "tdd", "TDD", "write tests first", "# TDD\nWrite the test first.", []string{"testing"}, false, "1.0.0", now)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixSkillSource, created.ID) || created.Slug != "tdd" || created.Version != "1.0.0" {
		t.Fatalf("%#v", created)
	}
	if _, ok := created.PublicJSON()["instructions"]; ok {
		t.Fatal("instructions projected")
	}
	listed, err := store.List("owner", "", "", "", 50)
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v %#v", err, listed)
	}
	other, err := store.List("other", "", "", "", 50)
	if err != nil || len(other) != 0 {
		t.Fatalf("isolation %#v", other)
	}
	if _, err := store.CreateCustom("owner", "tdd", "Dup", "", "# x", nil, false, "", now); err == nil {
		t.Fatal("duplicate slug")
	}
	archived, err := store.SetState("owner", created.ID, "archived", 1, now+1)
	if err != nil || archived.State != "archived" {
		t.Fatalf("%v %#v", err, archived)
	}
	set, err := store.CreateSet("owner", "core", "core skills", []SetItem{{
		SkillSourceID: created.ID, RevisionID: created.CurrentRevisionID.(string), Name: "tdd",
	}}, now+2)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.Preview("owner", []PreviewRequest{{SkillSetID: set.ID, ExpectedGeneration: 1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	excluded, _ := preview["excluded"].([]map[string]any)
	if len(excluded) != 1 {
		t.Fatalf("archived skill should be excluded %#v", preview)
	}
	if err := store.DeleteSet("owner", set.ID, 1); err != nil {
		t.Fatal(err)
	}
}

func TestImportCancelConflict(t *testing.T) {
	store := openStore(t)
	job, err := store.StartImport("owner", "skills-sh", "test-driven-development", 1)
	if err != nil || job.State != "queued" {
		t.Fatalf("%v %#v", err, job)
	}
	cancelled, err := store.CancelImport("owner", job.ID, 2)
	if err != nil || cancelled.State != "cancelled" {
		t.Fatalf("%v %#v", err, cancelled)
	}
	if _, err := store.CancelImport("owner", job.ID, 3); err == nil {
		t.Fatal("terminal cancel")
	}
}

func TestRegistryListReadsCacheNotCatalog(t *testing.T) {
	store := openStore(t)
	if err := store.UpsertCacheEntry(CacheEntry{
		CacheKey: "tkc_registry", OwnerID: "owner", SourceIdentity: "registry:skills-sh:anthropics/skills",
		ResolvedRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AdapterVersion: 1, BundleSHA256: "b" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Status: "READY", ByteCount: 1024, FileCount: 3, CreatedAt: 1, LastUsedAt: 2,
	}); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListRegistry("owner", "")
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v %#v", err, listed)
	}
	if listed[0]["cacheState"] != "READY" || listed[0]["lockState"] != "unlocked" || listed[0]["provider"] != "skills-sh" {
		t.Fatalf("%#v", listed[0])
	}
	filtered, err := store.ListRegistry("owner", "skillx")
	if err != nil || len(filtered) != 0 {
		t.Fatalf("filter %#v", filtered)
	}
	if err := store.UpsertCatalogEntry("owner", "skills-sh", "anthropics/skills/pdf", "anthropics/skills/pdf", "", `{"action":"install"}`, 3); err != nil {
		t.Fatal(err)
	}
	catalog, err := store.ListCatalogEntries("owner", "skills-sh")
	if err != nil || len(catalog) != 1 || catalog[0].Slug != "anthropics/skills/pdf" {
		t.Fatalf("%v %#v", err, catalog)
	}
	again, err := store.ListRegistry("owner", "")
	if err != nil || len(again) != 1 {
		t.Fatalf("catalog must not appear in list %#v", again)
	}
}
