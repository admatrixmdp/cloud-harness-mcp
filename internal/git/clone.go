package git

import (
	"context"
	"fmt"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// CloneRequest is a helper-container clone. Token is stdin-only.
type CloneRequest struct {
	Spec  HelperSpec
	Token string
}

// Cloner runs clone-helper.sh through the Docker CLI.
type Cloner struct {
	Engine sandbox.Engine
}

// Run clones with credential-free HTTPS URL in argv. Token rides stdin.
func (c Cloner) Run(ctx context.Context, req CloneRequest) (sandbox.Result, error) {
	if _, err := ValidateRepositoryURL(req.Spec.RepositoryURL, []string{"github.com"}); err != nil {
		return sandbox.Result{}, err
	}
	if err := ValidateHistorySpec(req.Spec.HistorySpec); err != nil {
		return sandbox.Result{}, err
	}
	args := CloneArgs(req.Spec)
	if ArgsContainSecret(args, req.Token) {
		return sandbox.Result{}, fmt.Errorf("%s: clone helper argv must not contain the token", protocol.ErrorInternal)
	}
	res, err := c.Engine.Invoke(ctx, args, sandbox.HelperStdin(req.Token))
	if err != nil {
		return res, err
	}
	if req.Token != "" {
		res.Stdout = RedactToken(res.Stdout, req.Token)
		res.Stderr = RedactToken(res.Stderr, req.Token)
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if msg == "" {
			msg = "clone helper failed"
		}
		return res, fmt.Errorf("%s: %s", protocol.ErrorUnavailable, msg)
	}
	return res, nil
}

// Transfer runs git-transfer-helper.sh. Import stays network-none; fetch/push may use bridge.
func (c Cloner) Transfer(ctx context.Context, mode TransferMode, spec HelperSpec, token string) (sandbox.Result, error) {
	if _, err := ValidateRepositoryURL(spec.RepositoryURL, []string{"github.com"}); err != nil {
		return sandbox.Result{}, err
	}
	args := TransferArgs(mode, spec)
	if ArgsContainSecret(args, token) {
		return sandbox.Result{}, fmt.Errorf("%s: transfer helper argv must not contain the token", protocol.ErrorInternal)
	}
	res, err := c.Engine.Invoke(ctx, args, sandbox.HelperStdin(token))
	if err != nil {
		return res, err
	}
	if token != "" {
		res.Stdout = RedactToken(res.Stdout, token)
		res.Stderr = RedactToken(res.Stderr, token)
	}
	return res, nil
}

// GH runs gh-helper.sh. Token rides stdin; argv never includes GH_TOKEN.
func (c Cloner) GH(ctx context.Context, spec HelperSpec, token string) (sandbox.Result, error) {
	if _, err := ValidateRepositoryURL(spec.RepositoryURL, []string{"github.com"}); err != nil {
		return sandbox.Result{}, err
	}
	if _, ok := RequiredGitHubPermissions(spec.Action); !ok {
		return sandbox.Result{}, fmt.Errorf("%s: unsupported github_action: %s", protocol.ErrorInvalidInput, spec.Action)
	}
	args := GHArgs(spec)
	if ArgsContainSecret(args, token) {
		return sandbox.Result{}, fmt.Errorf("%s: gh helper argv must not contain the token", protocol.ErrorInternal)
	}
	res, err := c.Engine.Invoke(ctx, args, sandbox.HelperStdin(token))
	if err != nil {
		return res, err
	}
	if token != "" {
		res.Stdout = RedactToken(res.Stdout, token)
		res.Stderr = RedactToken(res.Stderr, token)
	}
	return res, nil
}

// StdinWasUsed reports whether the docker runner received a token line matching token.
func StdinWasUsed(gotStdin, token string) bool {
	return strings.TrimSpace(gotStdin) == token
}
