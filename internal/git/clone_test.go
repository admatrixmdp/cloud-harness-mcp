package git

import (
	"context"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
)

func TestClonePassesTokenOnStdinOnly(t *testing.T) {
	var seenArgs []string
	var seenStdin string
	engine := sandbox.Engine{
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			seenArgs = append([]string{}, args...)
			seenStdin = stdin
			return sandbox.Result{ExitCode: 0, Stdout: "cloned ghs_this-is-not-a-real-token-value ok"}, nil
		},
	}
	token := "ghs_this-is-not-a-real-token-value"
	res, err := (Cloner{Engine: engine}).Run(context.Background(), CloneRequest{
		Spec: HelperSpec{
			Name: "chm-clone", Image: "cloud-harness-executor:local",
			WorkspaceID: "ws_abcdefghijklmnopqrstuvwx", JobPath: "/jobs/ws",
			RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		},
		Token: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ArgsContainSecret(seenArgs, token) {
		t.Fatalf("token in argv: %v", seenArgs)
	}
	if !StdinWasUsed(seenStdin, token) {
		t.Fatalf("stdin=%q", seenStdin)
	}
	if strings.Contains(res.Stdout, token) {
		t.Fatalf("token leaked in output: %s", res.Stdout)
	}
	if !strings.Contains(strings.Join(seenArgs, " "), "clone-helper.sh") {
		t.Fatal("missing helper")
	}
}

func TestCloneRejectsUserinfoURL(t *testing.T) {
	_, err := (Cloner{Engine: sandbox.Engine{Run: func(context.Context, []string, string) (sandbox.Result, error) {
		t.Fatal("must not run docker")
		return sandbox.Result{}, nil
	}}}).Run(context.Background(), CloneRequest{
		Spec: HelperSpec{RepositoryURL: "https://x-access-token:ghs_leak@github.com/a/b.git", JobPath: "/jobs/ws", Image: "img", Name: "n"},
	})
	if err == nil {
		t.Fatal("userinfo URL accepted")
	}
}

func TestTransferImportNetworkNone(t *testing.T) {
	var seen []string
	engine := sandbox.Engine{Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
		seen = args
		return sandbox.Result{ExitCode: 0}, nil
	}}
	_, err := (Cloner{Engine: engine}).Transfer(context.Background(), TransferImport, HelperSpec{
		Name: "chm-import", Image: "img", JobPath: "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp", TransferName: "t.git",
	}, "ghs_this-is-not-a-real-token-value")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(seen, " "), "--network none") {
		t.Fatalf("%v", seen)
	}
	if ArgsContainSecret(seen, "ghs_this-is-not-a-real-token-value") {
		t.Fatal("token in argv")
	}
}

func TestGHPassesTokenOnStdinOnly(t *testing.T) {
	var seenArgs []string
	var seenStdin string
	token := "ghs_this-is-not-a-real-token-value"
	engine := sandbox.Engine{Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
		seenArgs = append([]string{}, args...)
		seenStdin = stdin
		return sandbox.Result{ExitCode: 0, Stdout: "listed " + token}, nil
	}}
	res, err := (Cloner{Engine: engine}).GH(context.Background(), HelperSpec{
		Name: "chm-gh", Image: "img", JobPath: "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		Action:        "pr_list",
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if ArgsContainSecret(seenArgs, token) {
		t.Fatal("token in argv")
	}
	if !StdinWasUsed(seenStdin, token) {
		t.Fatalf("stdin=%q", seenStdin)
	}
	if strings.Contains(res.Stdout, token) {
		t.Fatal("token leaked in output")
	}
	if _, err := (Cloner{Engine: engine}).GH(context.Background(), HelperSpec{
		Name: "chm-gh", Image: "img", JobPath: "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
		Action:        "not_a_real_action",
	}, token); err == nil {
		t.Fatal("unknown action")
	}
}
