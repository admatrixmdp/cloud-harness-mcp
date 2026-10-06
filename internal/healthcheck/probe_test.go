package healthcheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeOKAndFailure(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ok.Close)
	if Probe(ok.URL) != 0 {
		t.Fatal("ok")
	}
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(fail.Close)
	if Probe(fail.URL) != 1 {
		t.Fatal("503 must fail")
	}
	if Probe("http://127.0.0.1:1/") != 1 {
		t.Fatal("refused must fail")
	}
}

func TestTCPProbeConnectAndRefuse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	if TCPProbe(ln.Addr().String(), time.Second) != 0 {
		t.Fatal("listening address must succeed")
	}
	if TCPProbe("127.0.0.1:1", 200*time.Millisecond) != 1 {
		t.Fatal("refused must fail")
	}
	if TCPProbe("", time.Second) != 1 {
		t.Fatal("empty address must fail")
	}
}
