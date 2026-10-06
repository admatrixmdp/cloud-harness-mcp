package provisioning

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func proxyClient(addr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
}

func TestProxyForbidsPrivateCONNECTAndNonAllowlistedHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := Config{
		ListenHost:   "127.0.0.1",
		ListenPort:   3128,
		AllowedHosts: []string{"github.com"},
		Lookup: func(host string) ([]net.IP, error) {
			if host == "github.com" {
				return []net.IP{net.ParseIP("140.82.121.4")}, nil
			}
			if host == "metadata.google.internal" {
				return []net.IP{net.ParseIP("169.254.169.254")}, nil
			}
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
		Dial: func(network, address string) (net.Conn, error) {
			t.Fatalf("dial must not run for forbidden destinations: %s", address)
			return nil, nil
		},
	}
	srv := &http.Server{Handler: &proxy{cfg: cfg}}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	client := proxyClient(ln.Addr().String())

	res, err := client.Get("http://evil-attacker.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "not allowlisted") {
		t.Fatalf("http %d %s", res.StatusCode, body)
	}

	res, err = client.Get("http://metadata.google.internal/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("metadata %d %s", res.StatusCode, body)
	}

	meta := cfg
	meta.AllowedHosts = []string{"metadata.google.internal"}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln2.Close() })
	srv2 := &http.Server{Handler: &proxy{cfg: meta}}
	go func() { _ = srv2.Serve(ln2) }()
	t.Cleanup(func() { _ = srv2.Close() })
	res, err = proxyClient(ln2.Addr().String()).Get("http://metadata.google.internal/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted metadata %d", res.StatusCode)
	}

	connect := func(hostPort string) string {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + hostPort + "\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, _ := io.ReadAll(bufio.NewReader(conn))
		return string(raw)
	}
	got := connect("github.com:80")
	if !strings.Contains(got, "403") || !strings.Contains(got, "only port 443") {
		t.Fatalf("port %q", got)
	}
	got = connect("evil.example:443")
	if !strings.Contains(got, "403") {
		t.Fatalf("host %q", got)
	}
}

func TestProxyCONNECTPipesToPinnedIP(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong!"))
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	upAddr := upstream.Addr().(*net.TCPAddr)
	cfg := Config{
		ListenHost:   "127.0.0.1",
		ListenPort:   3128,
		AllowedHosts: []string{"github.com"},
		Lookup:       func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("140.82.121.4")}, nil },
		Dial: func(network, address string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(address)
			if host != "140.82.121.4" || port != "443" {
				t.Fatalf("must pin CONNECT to validated IP:port, got %s", address)
			}
			return net.Dial("tcp", upAddr.String())
		},
	}
	srv := &http.Server{Handler: &proxy{cfg: cfg}}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("status %q %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "pong!" {
		t.Fatalf("pipe %q %v", got, err)
	}
}

func TestProxyHealthz(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{Handler: &proxy{cfg: Config{ListenHost: "127.0.0.1", ListenPort: 3128, AllowedHosts: []string{"github.com"}}}}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	res, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%d", res.StatusCode)
	}
}
