package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
)

const (
	dashboardCookie      = "__Host-ch-dashboard"
	sessionTTL           = 8 * time.Hour
	maxDashboardSessions = 1_000
	csrfHeader           = "x-csrf-token"
)

type dashboardSession struct {
	principalKey string
	tokenHash    [32]byte
	expiresAt    time.Time
	lastSeenAt   time.Time
}

// Sessions is the in-memory dashboard CSRF store. The cookie is HttpOnly;
// the CSRF token is hashed at rest and never logged.
type Sessions struct {
	mu       sync.Mutex
	sessions map[string]dashboardSession
	now      func() time.Time
}

func newSessions() *Sessions {
	return &Sessions{sessions: map[string]dashboardSession{}, now: time.Now}
}

func principalKey(id auth.RequestIdentity) string {
	raw, _ := json.Marshal(map[string]string{
		"mode":    string(id.Mode),
		"ownerId": id.OwnerID,
		"issuer":  id.Issuer,
		"subject": id.Subject,
	})
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("dashboard session: crypto/rand unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Sessions) pruneLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if !sess.expiresAt.After(now) {
			delete(s.sessions, id)
		}
	}
	for len(s.sessions) >= maxDashboardSessions {
		var oldestID string
		var oldest time.Time
		for id, sess := range s.sessions {
			if oldestID == "" || sess.lastSeenAt.Before(oldest) {
				oldestID = id
				oldest = sess.lastSeenAt
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.sessions, oldestID)
	}
}

func (s *Sessions) bootstrap(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	sid := randomToken()
	token := randomToken()
	now := s.now()
	s.sessions[sid] = dashboardSession{
		principalKey: principalKey(id),
		tokenHash:    sha256.Sum256([]byte(token)),
		expiresAt:    now.Add(sessionTTL),
		lastSeenAt:   now,
	}
	http.SetCookie(w, &http.Cookie{
		Name:     dashboardCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"csrfToken": token,
		"expiresAt": now.Add(sessionTTL).UTC().Format(time.RFC3339Nano),
	})
}

func (s *Sessions) verify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFrom(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended"})
			return
		}
		cookie, err := r.Cookie(dashboardCookie)
		token := r.Header.Get(csrfHeader)
		s.mu.Lock()
		var sess dashboardSession
		found := false
		if err == nil && cookie.Value != "" {
			sess, found = s.sessions[cookie.Value]
		}
		now := s.now()
		if !found || !sess.expiresAt.After(now) || sess.principalKey != principalKey(id) {
			s.mu.Unlock()
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended"})
			return
		}
		want := sess.tokenHash
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			s.mu.Unlock()
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "csrf_failed"})
			return
		}
		sess.lastSeenAt = now
		s.sessions[cookie.Value] = sess
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}
