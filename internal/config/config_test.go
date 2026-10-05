package config

import "testing"

func TestOptionsValid(t *testing.T) {
	http := Options{Transport: TransportHTTP}
	if err := http.Valid(); err != nil {
		t.Fatal(err)
	}
	stdio := Options{Transport: TransportStdio}
	if err := stdio.Valid(); err == nil {
		t.Fatal("stdio without workspace must fail")
	}
	ok := Options{Transport: TransportStdio, Workspace: "/tmp/proj"}
	if err := ok.Valid(); err != nil {
		t.Fatal(err)
	}
	httpWS := Options{Transport: TransportHTTP, Workspace: "/tmp/proj"}
	if err := httpWS.Valid(); err == nil {
		t.Fatal("http+workspace must fail")
	}
	push := Options{Transport: TransportStdio, Workspace: "/tmp/proj", GitPush: true}
	if err := push.Valid(); err != nil {
		t.Fatal(err)
	}
	if !push.GitNetwork {
		t.Fatal("git-push must imply git-network")
	}
}
