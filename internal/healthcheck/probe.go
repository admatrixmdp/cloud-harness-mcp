package healthcheck

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Probe GETs url and returns a process exit code. Distroless images have no
// node/curl; Compose healthchecks invoke the same binary with --healthcheck.
func Probe(url string) int {
	if url == "" {
		fmt.Fprintln(os.Stderr, "healthcheck url is required")
		return 1
	}
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// ProbeListen GETs path on listen, rewriting 0.0.0.0/:: to 127.0.0.1.
func ProbeListen(listen, path string) int {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	return Probe("http://" + net.JoinHostPort(host, port) + path)
}

// MaybeExit runs Probe when flag is set. "auto" uses ProbeListen.
func MaybeExit(flag, listen, path string) {
	if flag == "" {
		return
	}
	if flag == "auto" {
		os.Exit(ProbeListen(listen, path))
	}
	os.Exit(Probe(flag))
}

// TCPProbe dials host:port and returns a process exit code. Distroless agent
// images have no node/nc; isolation tests exec the same binary with --probe.
func TCPProbe(addr string, timeout time.Duration) int {
	if addr == "" {
		fmt.Fprintln(os.Stderr, "probe address is required")
		return 1
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 1
	}
	_ = conn.Close()
	return 0
}
