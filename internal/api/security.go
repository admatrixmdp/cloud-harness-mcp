package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SecurityConfig is the Host/Origin allowlist from ApiConfig.
type SecurityConfig struct {
	PublicHosts     []string
	AllowedOrigins  []string
	PreAuthMax      int
	PreAuthActive   int
	PrincipalMax    int
	PrincipalActive int
}

func (c SecurityConfig) withDefaults() SecurityConfig {
	if c.PreAuthMax == 0 {
		c.PreAuthMax = 1000
	}
	if c.PreAuthActive == 0 {
		c.PreAuthActive = 32
	}
	if c.PrincipalMax == 0 {
		c.PrincipalMax = 120
	}
	if c.PrincipalActive == 0 {
		c.PrincipalActive = 8
	}
	return c
}

type limitWindow struct {
	startedAt  time.Time
	lastSeenAt time.Time
	requests   int
	active     int
}

// RequestSecurity enforces Host/Origin allowlists, security headers, and
// pre-auth rate limits. Empty PublicHosts skips host checks (local tests).
func RequestSecurity(cfg SecurityConfig, next http.Handler) http.Handler {
	cfg = cfg.withDefaults()
	hosts := map[string]struct{}{}
	for _, h := range cfg.PublicHosts {
		hosts[strings.ToLower(h)] = struct{}{}
	}
	origins := map[string]struct{}{}
	for _, raw := range cfg.AllowedOrigins {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		origins[u.Scheme+"://"+u.Host] = struct{}{}
	}
	window := &limitWindow{startedAt: time.Now(), lastSeenAt: time.Now()}
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(hosts) > 0 {
			host := hostnameFromHost(r.Host)
			if _, ok := hosts[host]; !ok {
				writeSecurityError(w, http.StatusForbidden, "forbidden_host")
				return
			}
		}
		if raw := r.Header.Get("Origin"); raw != "" {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				writeSecurityError(w, http.StatusForbidden, "forbidden_origin")
				return
			}
			if _, ok := origins[u.Scheme+"://"+u.Host]; !ok {
				writeSecurityError(w, http.StatusForbidden, "forbidden_origin")
				return
			}
		}
		mu.Lock()
		now := time.Now()
		if now.Sub(window.startedAt) >= time.Minute {
			window.startedAt = now
			window.requests = 0
		}
		window.requests++
		window.lastSeenAt = now
		if window.requests > cfg.PreAuthMax || window.active >= cfg.PreAuthActive {
			mu.Unlock()
			w.Header().Set("Retry-After", "1")
			writeSecurityError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		window.active++
		mu.Unlock()
		defer func() {
			mu.Lock()
			if window.active > 0 {
				window.active--
			}
			mu.Unlock()
		}()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Accel-Buffering", "no")
		next.ServeHTTP(w, r)
	})
}

func hostnameFromHost(raw string) string {
	raw = strings.ToLower(raw)
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end > 1 {
			return raw[1:end]
		}
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return host
	}
	return raw
}

func writeSecurityError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": code})
}
