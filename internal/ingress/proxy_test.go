package ingress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestFromEnvRejectsInvalidPorts(t *testing.T) {
	t.Setenv("INGRESS_PORT", "0")
	if _, err := FromEnv(); err == nil {
		t.Fatal("port 0 must fail")
	}
	t.Setenv("INGRESS_PORT", "3100")
	t.Setenv("API_UPSTREAM_PORT", "70000")
	if _, err := FromEnv(); err == nil {
		t.Fatal("out of range upstream port must fail")
	}
}

func TestProxyForwardsHTTPBytesAndClosesBothSides(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upLn.Close() })
	disconnected := make(chan struct{})
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				req := string(buf[:n])
				if strings.Contains(req, "/stream") {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstream-open"))
					_, _ = conn.Read(buf)
					close(disconnected)
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Forwarded-Method: GET\r\nContent-Length: 8\r\n\r\nproxy-ok")
			}(c)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := proxyLn.Addr().(*net.TCPAddr).Port
	_ = proxyLn.Close()
	cfg := Config{
		ListenHost:   "127.0.0.1",
		ListenPort:   listenPort,
		UpstreamHost: "127.0.0.1",
		UpstreamPort: upLn.Addr().(*net.TCPAddr).Port,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- ListenAndServe(ctx, cfg) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", listenPort))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "proxy-ok" {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if res.Header.Get("X-Forwarded-Method") != "GET" {
		t.Fatalf("headers %v", res.Header)
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/stream", listenPort), nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = res.Body.Read(make([]byte, 4))
	res.Body.Close()
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream close did not tear down upstream")
	}
}

func TestConfigRejectsSecretShapedListen(t *testing.T) {
	// Ingress must still start with only host/port env; no token fields exist on Config.
	cfg := Config{ListenHost: "127.0.0.1", ListenPort: 3100, UpstreamHost: "api", UpstreamPort: 3000}
	if err := cfg.Valid(); err != nil {
		t.Fatal(err)
	}
}
