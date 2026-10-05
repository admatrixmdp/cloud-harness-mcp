package git

import "testing"

func TestValidateRepositoryURL(t *testing.T) {
	allowed := []string{"github.com"}
	if _, err := ValidateRepositoryURL("https://github.com/bestagentkits/cloud-harness-mcp", allowed); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRepositoryURL("https://user:token@github.com/org/repo", allowed); err == nil {
		t.Fatal("credentialed URL must fail")
	}
	if _, err := ValidateRepositoryURL("git@github.com:org/repo.git", allowed); err == nil {
		t.Fatal("ssh URL must fail")
	}
	if _, err := ValidateRepositoryURL("file:///etc/passwd", allowed); err == nil {
		t.Fatal("file URL must fail")
	}
	if _, err := ValidateRepositoryURL("https://evil.example/org/repo", allowed); err == nil {
		t.Fatal("non-allowlisted host must fail")
	}
	if _, err := ValidateRepositoryURL("https://127.0.0.1/repo.git", []string{"127.0.0.1"}); err == nil {
		t.Fatal("loopback host must fail even when allowlisted")
	}
}

func TestAddressForbidden(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "169.254.1.1"} {
		if !AddressForbidden(addr) {
			t.Fatalf("%s should be forbidden", addr)
		}
	}
	if AddressForbidden("1.1.1.1") {
		t.Fatal("public resolver must be allowed")
	}
}
