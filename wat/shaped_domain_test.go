package wat

// H7 (audit 2026-11-04): every key-derivation domain in this package must use the module path exactly. These domains
// are per-PSK wire constants of the shaped carriers: fixing a typo after a release would break every deployed peer
// (the strip would reject all frames), so the module path is pinned here and the source scan catches any new domain
// that copies the wrong spelling.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auditModulePath is github.com/JohnWatsoon/WatTunnel (go.mod); hardcoded once, as the audit requires.
const auditModulePath = "github.com/JohnWatsoon/WatTunnel"

func TestShapeDerivationDomainsUseModulePath(t *testing.T) {
	for _, c := range []struct {
		name, domain string
	}{
		{"rawshape", rawShapeDomain},
		{"udpshape", udpShapeDomain},
	} {
		if !strings.HasPrefix(c.domain, auditModulePath+"/") {
			t.Errorf("%s derivation domain %q does not start with %s/", c.name, c.domain, auditModulePath)
		}
	}
	// No Go file in the package may spell the module path with the old typo. Scan the sources so a future domain
	// cannot reintroduce it; tests run with the package directory as CWD.
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot list package sources: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// split so this test file does not match itself
		bad := "github.com/JohnWat" + "son/WatTunnel"
		if strings.Contains(string(b), bad) {
			t.Errorf("%s contains a derivation domain with the misspelled module path %q", f, bad)
		}
	}
}
