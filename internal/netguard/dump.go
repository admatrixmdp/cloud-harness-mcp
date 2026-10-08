package netguard

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const defaultBinary = "iptables-save"

var searchPaths = []string{
	"/sbin/iptables-save",
	"/usr/sbin/iptables-save",
	"/usr/bin/iptables-save",
}

// Options injects lookup and exec for tests. Production uses PATH + sbin.
type Options struct {
	LookPath func(file string) (string, error)
	Command  func(name string, arg ...string) *exec.Cmd
}

// Dump writes the host iptables-save snapshot to w. Missing binary or a
// non-zero exit fails closed; this process never mounts docker.sock or
// prints secrets.
func Dump(w io.Writer, opts Options) error {
	look := opts.LookPath
	if look == nil {
		look = exec.LookPath
	}
	run := opts.Command
	if run == nil {
		run = exec.Command
	}
	bin, err := resolveBinary(look, opts.LookPath == nil)
	if err != nil {
		return err
	}
	cmd := run(bin)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("iptables-save failed (exit code %d)", exit.ExitCode())
		}
		return fmt.Errorf("iptables-save failed: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("iptables-save write failed: %w", err)
	}
	return nil
}

func resolveBinary(look func(string) (string, error), allowHostFallback bool) (string, error) {
	if path, err := look(defaultBinary); err == nil && strings.TrimSpace(path) != "" {
		return path, nil
	}
	for _, candidate := range searchPaths {
		if path, err := look(candidate); err == nil && strings.TrimSpace(path) != "" {
			return path, nil
		}
	}
	// Host sbin fallback is production-only. Injected LookPath must be
	// able to prove "iptables-save is not available" on Ubuntu runners
	// that still ship /sbin/iptables-save.
	if allowHostFallback {
		for _, candidate := range searchPaths {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("iptables-save is not available")
}
