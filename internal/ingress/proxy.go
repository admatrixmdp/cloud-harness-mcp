package ingress

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Config is the credential-free TCP byte proxy. It must not receive secrets.
type Config struct {
	ListenHost   string
	ListenPort   int
	UpstreamHost string
	UpstreamPort int
}

// FromEnv reads INGRESS_* / API_UPSTREAM_* the same way deploy/ingress-proxy.mjs does.
func FromEnv() (Config, error) {
	cfg := Config{
		ListenHost:   getenv("INGRESS_HOST", "0.0.0.0"),
		ListenPort:   3100,
		UpstreamHost: getenv("API_UPSTREAM_HOST", "api"),
		UpstreamPort: 3000,
	}
	var err error
	if raw := os.Getenv("INGRESS_PORT"); raw != "" {
		cfg.ListenPort, err = parsePort(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ingress port")
		}
	}
	if raw := os.Getenv("API_UPSTREAM_PORT"); raw != "" {
		cfg.UpstreamPort, err = parsePort(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid API upstream port")
		}
	}
	if err := cfg.Valid(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Valid rejects out-of-range ports.
func (c Config) Valid() error {
	if c.ListenHost == "" || c.UpstreamHost == "" {
		return fmt.Errorf("ingress host and upstream host are required")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("invalid ingress port")
	}
	if c.UpstreamPort < 1 || c.UpstreamPort > 65535 {
		return fmt.Errorf("invalid API upstream port")
	}
	return nil
}

func (c Config) listenAddr() string {
	return net.JoinHostPort(c.ListenHost, strconv.Itoa(c.ListenPort))
}

func (c Config) upstreamAddr() string {
	return net.JoinHostPort(c.UpstreamHost, strconv.Itoa(c.UpstreamPort))
}

// ListenAndServe pipes raw TCP bytes to the private API. No HTTP parsing, no
// headers, no credentials. Closing either side tears down the other.
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
	fmt.Fprintf(os.Stdout, "ingress proxy listening on %s\n", cfg.listenAddr())
	for {
		down, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go pipe(down, cfg.upstreamAddr())
	}
}

func pipe(down net.Conn, upstreamAddr string) {
	defer down.Close()
	up, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	copyClose := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.SetDeadline(time.Now())
		_ = src.SetDeadline(time.Now())
	}
	go copyClose(up, down)
	go copyClose(down, up)
	wg.Wait()
}

func parsePort(raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port")
	}
	return n, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
