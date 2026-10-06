package githubapp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	defaultMaxPages = 10
	defaultMaxRepos = 1_000
	defaultTimeout  = 10 * time.Second
	pageSize        = 100
)

// HTTPVerifier confirms a GitHub App installation against api.github.com.
// Tests inject Client; production uses the runner HTTP client.
type HTTPVerifier struct {
	AppID      string
	PrivateKey []byte
	Client     *http.Client
	Now        func() time.Time
	MaxPages   int
	MaxRepos   int
	Timeout    time.Duration
}

func NewHTTPVerifier(cfg git.AppConfig, client *http.Client) *HTTPVerifier {
	return &HTTPVerifier{
		AppID:      cfg.AppID,
		PrivateKey: cfg.PrivateKey,
		Client:     client,
		Now:        time.Now,
		MaxPages:   defaultMaxPages,
		MaxRepos:   defaultMaxRepos,
		Timeout:    defaultTimeout,
	}
}

func (v *HTTPVerifier) VerifyInstallation(installationID string) (Verified, error) {
	if v == nil || strings.TrimSpace(v.AppID) == "" || len(v.PrivateKey) == 0 {
		return Verified{}, fmt.Errorf("%s: GitHub App setup is not configured", protocol.ErrorUnavailable)
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	deadline := now.Add(v.timeout())
	jwt, err := git.AppJWT(git.AppConfig{AppID: v.AppID, PrivateKey: v.PrivateKey}, now)
	if err != nil {
		return Verified{}, fmt.Errorf("%s: GitHub App authentication failed", protocol.ErrorUnavailable)
	}
	var payload installationPayload
	if err := v.getJSON("/app/installations/"+urlPath(installationID), jwt, deadline, &payload); err != nil {
		return Verified{}, err
	}
	token, err := v.mintInstallationToken(installationID, jwt, deadline)
	if err != nil {
		return Verified{}, err
	}
	repos, err := v.listRepositories(token, deadline)
	if err != nil {
		return Verified{}, err
	}
	if payload.ID == 0 || payload.AppID == 0 || payload.Account.ID == 0 || payload.Account.Login == "" {
		return Verified{}, fmt.Errorf("%s: GitHub returned an invalid installation record", protocol.ErrorUnavailable)
	}
	status := "active"
	if payload.SuspendedAt != "" {
		status = "suspended"
	}
	out := Verified{
		AppID:          strconv.FormatInt(payload.AppID, 10),
		InstallationID: strconv.FormatInt(payload.ID, 10),
		AccountID:      strconv.FormatInt(payload.Account.ID, 10),
		AccountLogin:   payload.Account.Login,
		Issues:         permissionLevel(payload.Permissions.Issues),
		PullRequests:   permissionLevel(payload.Permissions.PullRequests),
		Status:         status,
		Repositories:   make([]VerifiedRepo, 0, len(repos)),
	}
	installWrite := payload.Permissions.Contents == "write"
	for _, repo := range repos {
		contents := repo.Contents
		if installWrite {
			contents = "write"
		}
		out.Repositories = append(out.Repositories, VerifiedRepo{
			Owner:      repo.Owner,
			Repository: repo.Repository,
			Contents:   contents,
		})
	}
	return out, nil
}

type installationPayload struct {
	ID          int64  `json:"id"`
	AppID       int64  `json:"app_id"`
	SuspendedAt string `json:"suspended_at"`
	Account     struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"account"`
	Permissions struct {
		Contents     string `json:"contents"`
		Issues       string `json:"issues"`
		PullRequests string `json:"pull_requests"`
	} `json:"permissions"`
}

type repositoriesPayload struct {
	TotalCount   int `json:"total_count"`
	Repositories []struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		Permissions struct {
			Contents string `json:"contents"`
			Push     bool   `json:"push"`
			Pull     bool   `json:"pull"`
		} `json:"permissions"`
	} `json:"repositories"`
}

func (v *HTTPVerifier) mintInstallationToken(installationID, _ string, deadline time.Time) (string, error) {
	cfg := git.AppConfig{AppID: v.AppID, InstallationID: installationID, PrivateKey: v.PrivateKey}
	req, err := git.MintRequest(cfg, "", v.now())
	if err != nil {
		return "", fmt.Errorf("%s: GitHub installation token creation failed", protocol.ErrorUnavailable)
	}
	raw, status, err := v.do(req, deadline)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", fmt.Errorf("%s: GitHub installation not found", protocol.ErrorNotFound)
	}
	if status >= 300 {
		return "", fmt.Errorf("%s: GitHub installation token creation failed", protocol.ErrorUnavailable)
	}
	minted, err := git.ParseMintResponse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: GitHub installation token creation failed", protocol.ErrorUnavailable)
	}
	return minted.Token, nil
}

func (v *HTTPVerifier) listRepositories(token string, deadline time.Time) ([]VerifiedRepo, error) {
	collected := make([]VerifiedRepo, 0)
	seen := map[string]struct{}{}
	var expected *int
	maxPages := v.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	maxRepos := v.MaxRepos
	if maxRepos <= 0 {
		maxRepos = defaultMaxRepos
	}
	for page := 1; page <= maxPages; page++ {
		var payload repositoriesPayload
		if err := v.getJSON("/installation/repositories?per_page="+strconv.Itoa(pageSize)+"&page="+strconv.Itoa(page), token, deadline, &payload); err != nil {
			return nil, err
		}
		if payload.Repositories == nil || payload.TotalCount < 0 {
			return nil, fmt.Errorf("%s: GitHub returned an invalid repository page", protocol.ErrorUnavailable)
		}
		if expected == nil {
			n := payload.TotalCount
			expected = &n
			if n > maxRepos {
				return nil, fmt.Errorf("%s: GitHub repository verification exceeded its completeness bound", protocol.ErrorLimitExceeded)
			}
		} else if payload.TotalCount != *expected {
			return nil, fmt.Errorf("%s: GitHub repository pagination changed during verification", protocol.ErrorUnavailable)
		}
		for _, repo := range payload.Repositories {
			if repo.Owner.Login == "" || repo.Name == "" {
				return nil, fmt.Errorf("%s: GitHub returned an invalid repository record", protocol.ErrorUnavailable)
			}
			key := strings.ToLower(repo.Owner.Login) + "\x00" + strings.ToLower(repo.Name)
			if _, ok := seen[key]; ok {
				return nil, fmt.Errorf("%s: GitHub returned a duplicate repository record", protocol.ErrorUnavailable)
			}
			seen[key] = struct{}{}
			contents := "read"
			if repo.Permissions.Contents == "write" || repo.Permissions.Push {
				contents = "write"
			}
			collected = append(collected, VerifiedRepo{Owner: repo.Owner.Login, Repository: repo.Name, Contents: contents})
			if len(collected) > maxRepos || len(collected) > payload.TotalCount {
				return nil, fmt.Errorf("%s: GitHub repository verification exceeded its completeness bound", protocol.ErrorLimitExceeded)
			}
		}
		if len(collected) == payload.TotalCount {
			return collected, nil
		}
		if len(payload.Repositories) != pageSize {
			return nil, fmt.Errorf("%s: GitHub returned an incomplete repository list", protocol.ErrorUnavailable)
		}
	}
	return nil, fmt.Errorf("%s: GitHub repository verification exceeded its completeness bound", protocol.ErrorLimitExceeded)
}

func (v *HTTPVerifier) getJSON(path, token string, deadline time.Time, dest any) error {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return fmt.Errorf("%s: GitHub installation verification failed", protocol.ErrorUnavailable)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	raw, status, err := v.do(req, deadline)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return fmt.Errorf("%s: GitHub installation not found", protocol.ErrorNotFound)
	}
	if status >= 300 {
		return fmt.Errorf("%s: GitHub installation verification failed", protocol.ErrorUnavailable)
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("%s: GitHub returned an invalid installation record", protocol.ErrorUnavailable)
	}
	return nil
}

func (v *HTTPVerifier) do(req *http.Request, deadline time.Time) ([]byte, int, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, 0, fmt.Errorf("%s: GitHub installation verification timed out", protocol.ErrorTimeout)
	}
	client := v.Client
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(strings.ToLower(err.Error()), "deadline") {
			return nil, 0, fmt.Errorf("%s: GitHub installation verification timed out", protocol.ErrorTimeout)
		}
		return nil, 0, fmt.Errorf("%s: GitHub installation verification failed", protocol.ErrorUnavailable)
	}
	defer res.Body.Close()
	if time.Now().After(deadline) {
		return nil, 0, fmt.Errorf("%s: GitHub installation verification timed out", protocol.ErrorTimeout)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: GitHub installation verification failed", protocol.ErrorUnavailable)
	}
	return raw, res.StatusCode, nil
}

func (v *HTTPVerifier) timeout() time.Duration {
	if v.Timeout > 0 {
		return v.Timeout
	}
	return defaultTimeout
}

func (v *HTTPVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func permissionLevel(granted string) string {
	if granted == "write" || granted == "read" {
		return granted
	}
	return "none"
}

func urlPath(id string) string {
	id = strings.TrimSpace(id)
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return ""
	}
	return id
}
