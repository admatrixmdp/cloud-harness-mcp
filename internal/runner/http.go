package runner

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Options configure the runner HTTP RPC.
type Options struct {
	ServiceToken string
	Service      *Service
}

// Handler is the runner mux. This process is the Docker authority.
func Handler(opts Options) http.Handler {
	svc := opts.Service
	if svc == nil {
		svc = NewService(Config{}, nil, nil)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/v1/operations", withServiceToken(opts.ServiceToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleOperation(w, r, svc)
	})))
	return mux
}

func handleOperation(w http.ResponseWriter, r *http.Request, svc *Service) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req protocol.RunnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeResult(w, http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "invalid runner request", false))
		return
	}
	if !req.Operation.Known() {
		writeResult(w, http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "unknown operation", false))
		return
	}
	result := svc.Execute(r.Context(), req)
	status := http.StatusOK
	if !result.OK {
		status = statusFor(result)
	}
	writeResult(w, status, result)
}

func statusFor(result protocol.ToolResult) int {
	if result.Error == nil {
		return http.StatusBadRequest
	}
	switch result.Error.Code {
	case protocol.ErrorAuthenticationFailed:
		return http.StatusUnauthorized
	case protocol.ErrorForbidden:
		return http.StatusForbidden
	case protocol.ErrorNotFound:
		return http.StatusNotFound
	case protocol.ErrorExpired:
		return http.StatusGone
	case protocol.ErrorConflict, protocol.ErrorStaleGeneration, protocol.ErrorStaleHead:
		return http.StatusConflict
	case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
		return http.StatusServiceUnavailable
	case protocol.ErrorTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadRequest
	}
}

func withServiceToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		prefix := []byte("Bearer ")
		if len(got) <= len(prefix) || subtle.ConstantTimeCompare(got[len(prefix):], want) != 1 {
			writeResult(w, http.StatusUnauthorized, protocol.Fail(protocol.ErrorAuthenticationFailed, "authentication failed", false))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeResult(w http.ResponseWriter, status int, result protocol.ToolResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
