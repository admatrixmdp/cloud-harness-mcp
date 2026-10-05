package git

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// TransferMode is a git-transfer-helper.sh mode.
type TransferMode string

const (
	TransferFetch     TransferMode = "fetch"
	TransferImport    TransferMode = "import"
	TransferStagePush TransferMode = "stage-push"
	TransferPush      TransferMode = "push"
)

// HelperSpec describes an ephemeral helper container. The token is never a
// docker argument; callers pass it only as process stdin.
type HelperSpec struct {
	Name          string
	Image         string
	InstanceID    string
	WorkspaceID   string
	JobPath       string
	RepositoryURL string
	Ref           string
	HistorySpec   string
	CachePath     string
	TransferName  string
	Argument      string
	ExpectedOID   string
	Action        string
	ActionArgs    []string
}

// CloneArgs is docker run argv for clone-helper.sh.
func CloneArgs(spec HelperSpec) []string {
	args := helperBase(spec, "clone-helper", "bridge")
	args = append(args,
		"--volume", spec.JobPath+":/job",
	)
	if spec.CachePath != "" {
		args = append(args, "--volume", spec.CachePath+":/job/cache:ro")
	}
	args = append(args,
		"--entrypoint", "/opt/harness/clone-helper.sh", spec.Image,
		spec.RepositoryURL, "/job/repo", spec.Ref, cacheArg(spec.CachePath), spec.HistorySpec,
	)
	return args
}

// TransferArgs is docker run argv for git-transfer-helper.sh.
func TransferArgs(mode TransferMode, spec HelperSpec) []string {
	network := "none"
	if mode == TransferFetch || mode == TransferPush {
		network = "bridge"
	}
	args := helperBase(spec, "git-transfer-helper", network)
	args = append(args,
		"--volume", spec.JobPath+":/job:rw",
		"--entrypoint", "/opt/harness/git-transfer-helper.sh", spec.Image,
		string(mode), spec.RepositoryURL, "/job/repo", "/job/"+spec.TransferName,
		spec.Argument, spec.ExpectedOID, spec.HistorySpec,
	)
	return args
}

// GHArgs is docker run argv for gh-helper.sh. Token still stdin-only.
func GHArgs(spec HelperSpec) []string {
	args := helperBase(spec, "gh-helper", "bridge")
	args = append(args,
		"--volume", spec.JobPath+"/repo:/workspace:ro",
		"--workdir", "/workspace",
		"--env", "GH_REPO="+ghRepoFromURL(spec.RepositoryURL),
		"--entrypoint", "/opt/harness/gh-helper.sh", spec.Image,
		spec.Action,
	)
	args = append(args, spec.ActionArgs...)
	return args
}

func helperBase(spec HelperSpec, role, network string) []string {
	return []string{
		"run", "-i", "--rm", "--pull", "never", "--name", spec.Name,
		"--label", sandbox.ManagedLabel,
		"--label", "cloud-harness.role=" + role,
		"--label", "cloud-harness.ephemeral=true",
		"--label", "cloud-harness.instance=" + spec.InstanceID,
		"--label", "cloud-harness.workspace=" + spec.WorkspaceID,
		"--network", network,
		"--user", sandbox.ExecutorUser,
		"--read-only",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "128",
		"--memory", "512m",
		"--memory-swap", "512m",
		"--cpus", "1",
		"--env", "HOME=/tmp/cloud-harness-home",
		"--env", "GIT_CONFIG_NOSYSTEM=1",
		"--env", "GIT_TERMINAL_PROMPT=0",
	}
}

func cacheArg(path string) string {
	if path == "" {
		return ""
	}
	return "/job/cache"
}

func ghRepoFromURL(raw string) string {
	u, err := urlMust(raw)
	if err != nil {
		return ""
	}
	repo, err := ParseGitHubRepository(u)
	if err != nil {
		return ""
	}
	return repo.Owner + "/" + repo.Name
}

func urlMust(raw string) (*url.URL, error) {
	return ValidateRepositoryURL(raw, []string{"github.com"})
}

// ValidateHistorySpec accepts ”, full, depth:N, or since:DATE.
func ValidateHistorySpec(spec string) error {
	switch {
	case spec == "" || spec == "full":
		return nil
	case strings.HasPrefix(spec, "depth:"):
		depth := strings.TrimPrefix(spec, "depth:")
		if len(depth) == 0 || depth[0] == '0' {
			return fmt.Errorf("%s: invalid fetch depth", protocol.ErrorInvalidInput)
		}
		for _, c := range depth {
			if c < '0' || c > '9' {
				return fmt.Errorf("%s: invalid fetch depth", protocol.ErrorInvalidInput)
			}
		}
		return nil
	case strings.HasPrefix(spec, "since:"):
		return nil
	default:
		return fmt.Errorf("%s: invalid fetch history spec", protocol.ErrorInvalidInput)
	}
}

// FetchHistorySpec maps git_fetch options onto the helper positional spec.
func FetchHistorySpec(depth *int, unshallow bool, shallowSince string) (string, error) {
	selected := 0
	if depth != nil {
		selected++
	}
	if unshallow {
		selected++
	}
	if shallowSince != "" {
		selected++
	}
	if selected > 1 {
		return "", fmt.Errorf("%s: choose at most one of depth, unshallow, or shallowSince", protocol.ErrorInvalidInput)
	}
	if unshallow {
		return "full", nil
	}
	if shallowSince != "" {
		return "since:" + shallowSince, nil
	}
	if depth != nil {
		return fmt.Sprintf("depth:%d", *depth), nil
	}
	return "", nil
}

// ValidFetchRef rejects option-like refs and destination refspecs.
func ValidFetchRef(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-") && !strings.Contains(value, "\x00") && !strings.Contains(value, ":") && len(value) <= 255
}

// NormalizePushRefspec constrains push to origin heads. Empty requested uses branch.
func NormalizePushRefspec(requested, branch string) (string, error) {
	refspec := requested
	if refspec == "" {
		if branch == "" {
			return "", fmt.Errorf("%s: git_push requires refspec when HEAD is detached", protocol.ErrorConflict)
		}
		refspec = "HEAD:refs/heads/" + branch
	}
	if strings.HasPrefix(refspec, "-") || strings.Contains(refspec, "\x00") || strings.HasPrefix(refspec, ":") {
		return "", fmt.Errorf("%s: invalid push refspec", protocol.ErrorInvalidInput)
	}
	if strings.Contains(refspec, "refs/tags/") || strings.Contains(refspec, "refs/notes/") {
		return "", fmt.Errorf("%s: invalid push refspec", protocol.ErrorInvalidInput)
	}
	return refspec, nil
}

// ArgsContainSecret reports whether argv leaked a token or docker.sock.
func ArgsContainSecret(args []string, token string) bool {
	joined := strings.Join(args, " ")
	if token != "" && strings.Contains(joined, token) {
		return true
	}
	if strings.Contains(strings.ToLower(joined), "docker.sock") {
		return true
	}
	if strings.Contains(joined, "GH_TOKEN=") || strings.Contains(joined, "GITHUB_TOKEN=") {
		return true
	}
	return false
}

// OriginOnlyPush reports whether push argv targets origin rather than an arbitrary remote.
func OriginOnlyPush(args []string) bool {
	joined := strings.Join(args, " ")
	return strings.Contains(joined, "git-transfer-helper.sh") && strings.Contains(joined, string(TransferPush))
}
