package netguard

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDumpWritesIptablesSaveStdout(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "iptables-save")
	script := "#!/bin/sh\nprintf '*filter\\n-A FORWARD -j DOCKER-USER\\nCOMMIT\\n'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Dump(&out, Options{
		LookPath: func(string) (string, error) { return bin, nil },
		Command:  exec.Command,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "-A FORWARD -j DOCKER-USER") {
		t.Fatalf("stdout=%q", out.String())
	}
	if strings.Contains(out.String(), "docker.sock") || strings.Contains(out.String(), "TOKEN") {
		t.Fatalf("leaked: %q", out.String())
	}
}

func TestDumpFailsClosedWhenBinaryMissing(t *testing.T) {
	err := Dump(&bytes.Buffer{}, Options{
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
	if err == nil || !strings.Contains(err.Error(), "iptables-save is not available") {
		t.Fatalf("missing: %v", err)
	}
}

func TestDumpUsesHostSbinOnlyWithoutInjectedLookPath(t *testing.T) {
	if _, err := os.Stat("/sbin/iptables-save"); err != nil {
		t.Skip("no host iptables-save")
	}
	err := Dump(&bytes.Buffer{}, Options{})
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "iptables-save failed") {
		t.Fatalf("production fallback should invoke host binary: %v", err)
	}
}

func TestDumpFailsClosedOnNonzeroExit(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "iptables-save")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho boom >&2\nexit 4\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := Dump(&bytes.Buffer{}, Options{
		LookPath: func(string) (string, error) { return bin, nil },
		Command:  exec.Command,
	})
	if err == nil || !strings.Contains(err.Error(), "exit code 4") {
		t.Fatalf("nonzero: %v", err)
	}
}
