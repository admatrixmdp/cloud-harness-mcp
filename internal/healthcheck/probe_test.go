package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
