package provisioning

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	forbiddenHTTP    = "Forbidden: destination host is not allowlisted or resolves to a forbidden IP address\n"
	forbiddenCONNECT = "Forbidden: destination is not allowlisted or resolves to forbidden IP\r\n"
	forbiddenPort    = "Forbidden: only port 443 is permitted for CONNECT\r\n"
)

// ListenAndServe starts the HTTP/CONNECT egress proxy. Helpers already carry
// only allowlisted destinations; this process never attaches credentials.
func ListenAndServe(ctx context.Context, cfg Config) error {
	if err := cfg.Valid(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.listenAddr())
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	fmt.Fprintf(os.Stdout, "provisioning proxy listening on %s\n", cfg.listenAddr())
	srv := &http.Server{
		Handler:           &proxy{cfg: cfg},
		ReadHeaderTimeout: 10 * time.Second,
	}
	err = srv.Serve(ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type proxy struct {
	cfg Config
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect && r.URL.Host == "" && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		http.Error(w, "Bad Request\n", http.StatusBadRequest)
		return
	}
	target, err := p.cfg.ResolveAndValidateHost(host)
	if err != nil {
		http.Error(w, forbiddenHTTP, http.StatusForbidden)
		return
	}
	port := r.URL.Port()
	if port == "" {
		port = "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
	}
	up, err := p.cfg.dial("tcp", net.JoinHostPort(target.IP.String(), port))
	if err != nil {
		http.Error(w, "Bad Gateway\n", http.StatusBadGateway)
		return
	}
	defer up.Close()
	if err := r.Write(up); err != nil {
		http.Error(w, "Bad Gateway\n", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Bad Gateway\n", http.StatusBadGateway)
		return
	}
	down, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer down.Close()
	pipe(down, up)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}
	if host == "" {
		http.Error(w, "Bad Request\n", http.StatusBadRequest)
		return
	}
	if n, convErr := strconv.Atoi(port); convErr != nil || n != 443 {
		http.Error(w, forbiddenPort, http.StatusForbidden)
		return
	}
	target, err := p.cfg.ResolveAndValidateHost(host)
	if err != nil {
		http.Error(w, forbiddenCONNECT, http.StatusForbidden)
		return
	}
	up, err := p.cfg.dial("tcp", net.JoinHostPort(target.IP.String(), "443"))
	if err != nil {
		http.Error(w, "Bad Gateway\n", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "Bad Gateway\n", http.StatusBadGateway)
		return
	}
	down, _, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	if _, err := down.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = up.Close()
		_ = down.Close()
		return
	}
	pipe(down, up)
}

func pipe(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	copyClose := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.SetDeadline(time.Now())
		_ = src.SetDeadline(time.Now())
	}
	go copyClose(a, b)
	go copyClose(b, a)
	wg.Wait()
}
