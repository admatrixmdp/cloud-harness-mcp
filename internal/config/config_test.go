package config

import "testing"

func TestOptionsValid(t *testing.T) {
	if err := (Options{Transport: TransportHTTP}).Valid(); err != nil {
		t.Fatal(err)
	}
	if err := (Options{Transport: TransportStdio}).Valid(); err == nil {
		t.Fatal("stdio without workspace must fail")
	}
	if err := (Options{Transport: TransportStdio, Workspace: "/tmp/proj"}).Valid(); err != nil {
		t.Fatal(err)
	}
}
