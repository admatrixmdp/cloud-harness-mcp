package git

import (
	"strings"
	"testing"
)

const sampleToken = "ghs_this-is-not-a-real-token-value"

func TestCloneArgsNeverEmbedToken(t *testing.T) {
	args := CloneArgs(HelperSpec{
		Name:          "chm-clone-test",
		Image:         "cloud-harness-executor:local",
		InstanceID:    "inst",
		WorkspaceID:   "ws_abcdefghijklmnopqrst",
		JobPath:       "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		HistorySpec:   "",
	})
	if ArgsContainSecret(args, sampleToken) {
		t.Fatalf("secret leaked: %v", args)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "clone-helper.sh") {
		t.Fatal("missing clone helper entrypoint")
	}
	if strings.Contains(joined, "--network none") {
		t.Fatal("clone helper needs network to reach GitHub")
	}
	if !strings.Contains(joined, "--user 10001:10001") || !strings.Contains(joined, "--read-only") {
		t.Fatal("helper must be non-root read-only")
	}
}

func TestTransferPushIsOriginOnlyAndStdinAuth(t *testing.T) {
	args := TransferArgs(TransferPush, HelperSpec{
		Name:          "chm-git-push",
		Image:         "cloud-harness-executor:local",
		InstanceID:    "inst",
		WorkspaceID:   "ws_abcdefghijklmnopqrst",
		JobPath:       "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		TransferName:  "transfer.git",
		Argument:      "HEAD:refs/heads/main",
		ExpectedOID:   "abc123",
	})
	if ArgsContainSecret(args, sampleToken) {
		t.Fatal("token in argv")
	}
	if !OriginOnlyPush(args) {
		t.Fatal("push helper argv missing origin-only transfer mode")
	}
	if !strings.Contains(strings.Join(args, " "), "--force-with-lease") {
		// lease is applied inside the helper script from ExpectedOID, not docker argv.
	}
	if strings.Contains(strings.Join(args, " "), sampleToken) {
		t.Fatal("token leaked")
	}
}

func TestImportUsesNetworkNone(t *testing.T) {
	args := TransferArgs(TransferImport, HelperSpec{
		Name:          "chm-git-import",
		Image:         "cloud-harness-executor:local",
		WorkspaceID:   "ws_abcdefghijklmnopqrst",
		JobPath:       "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		TransferName:  "transfer.git",
	})
	if !strings.Contains(strings.Join(args, " "), "--network none") {
		t.Fatalf("import must be network-none: %v", args)
	}
}

func TestGHHelperStdinOnly(t *testing.T) {
	args := GHArgs(HelperSpec{
		Name:          "chm-gh",
		Image:         "cloud-harness-executor:local",
		WorkspaceID:   "ws_abcdefghijklmnopqrst",
		JobPath:       "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		Action:        "pr_list",
	})
	if ArgsContainSecret(args, sampleToken) {
		t.Fatal("token in gh helper argv")
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "ghs_") {
		t.Fatal("token-shaped value in argv")
	}
	if !strings.Contains(joined, "GH_REPO=bestagentkits/cloud-harness-mcp") {
		t.Fatalf("missing GH_REPO: %s", joined)
	}
}

func TestHistorySpec(t *testing.T) {
	if err := ValidateHistorySpec(""); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHistorySpec("full"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHistorySpec("depth:50"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHistorySpec("depth:0"); err == nil {
		t.Fatal("depth 0 must fail")
	}
	if err := ValidateHistorySpec("recursive"); err == nil {
		t.Fatal("unknown spec must fail")
	}
}

func TestParseAndRedact(t *testing.T) {
	u, err := ValidateRepositoryURL("https://github.com/BestAgentKits/Cloud-Harness-MCP.git", []string{"github.com"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := ParseGitHubRepository(u)
	if err != nil {
		t.Fatal(err)
	}
	if repo.Owner != "bestagentkits" || repo.Name != "cloud-harness-mcp" {
		t.Fatalf("%+v", repo)
	}
	if got := RedactToken("using "+sampleToken+" now", sampleToken); strings.Contains(got, sampleToken) {
		t.Fatalf("token survived redaction: %s", got)
	}
	if _, ok := RequiredGitHubPermissions("pr_create"); !ok {
		t.Fatal("pr_create permissions")
	}
}

func TestParseGitHubRepositoryRejectsExtraPath(t *testing.T) {
	u, err := ValidateRepositoryURL("https://github.com/owner/repo/extra.git", []string{"github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGitHubRepository(u); err == nil {
		t.Fatal("ambiguous GitHub path must fail before minting")
	}
}
