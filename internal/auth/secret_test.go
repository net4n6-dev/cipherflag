package auth

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestLoadOrCreateSecret_CreatesWithModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "jwt.key")
	s, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 {
		t.Fatalf("len = %d, want 32", len(s))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 600", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(path))
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 700", di.Mode().Perm())
	}
}

func TestLoadOrCreateSecret_StableAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwt.key")
	a, _ := LoadOrCreateSecret(path)
	b, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("second call returned a different secret")
	}
}

func TestLoadOrCreateSecret_DifferentPathsDiffer(t *testing.T) {
	d := t.TempDir()
	a, _ := LoadOrCreateSecret(filepath.Join(d, "a"))
	b, _ := LoadOrCreateSecret(filepath.Join(d, "b"))
	if bytes.Equal(a, b) {
		t.Error("two installs produced the same secret")
	}
}

// Review focus 1: a short or empty file must stop startup.
func TestLoadOrCreateSecret_RejectsShortFile(t *testing.T) {
	for _, n := range []int{0, 1, 31} {
		path := filepath.Join(t.TempDir(), "jwt.key")
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, n), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadOrCreateSecret(path)
		if err == nil {
			t.Fatalf("%d-byte file accepted", n)
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name the path", err)
		}
	}
}

func TestLoadOrCreateSecret_UnwritableParentErrors(t *testing.T) {
	// A regular file where the parent directory should be. The test exits
	// through the read error (ENOTDIR reading a path under a regular file),
	// not MkdirAll. It still proves startup fails closed, and it works as root.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSecret(filepath.Join(blocker, "jwt.key")); err == nil {
		t.Fatal("expected an error when the parent is not a directory")
	}
}

func TestLoadOrCreateSecret_WarnsOnLooseMode(t *testing.T) {
	var buf bytes.Buffer
	old := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = old })

	path := filepath.Join(t.TempDir(), "jwt.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'k'}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	// A restrictive umask must not turn the file into 0600 before the check.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSecret(path); err != nil {
		t.Fatalf("loose mode must warn, not fail: %v", err)
	}
	if !strings.Contains(buf.String(), path) {
		t.Errorf("no warning naming %s; log = %q", path, buf.String())
	}
}

// Review focus 5: two replicas on one volume must agree, with no temp files left.
func TestLoadOrCreateSecret_ConcurrentFirstCallsAgree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt.key")
	const n = 16
	results := make([][]byte, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = LoadOrCreateSecret(path)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if !bytes.Equal(results[i], results[0]) {
			t.Fatalf("call %d returned a different secret", i)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "jwt.key" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only jwt.key", names)
	}
}

func TestLoadOrCreateToken_HexStableAndModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "setup-token")
	a, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 {
		t.Fatalf("len = %d, want 64", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Errorf("token is not hex: %v", err)
	}
	b, _ := LoadOrCreateToken(path)
	if a != b {
		t.Error("token changed between calls")
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 600", fi.Mode().Perm())
	}
}

// Review focus 2: hand-edited files with trailing whitespace still work.
func TestLoadOrCreateToken_TrimsWhitespace(t *testing.T) {
	want := strings.Repeat("ab", 32)
	for _, suffix := range []string{"\n", "\r\n", "  \n"} {
		path := filepath.Join(t.TempDir(), "setup-token")
		if err := os.WriteFile(path, []byte(want+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadOrCreateToken(path)
		if err != nil {
			t.Fatalf("suffix %q: %v", suffix, err)
		}
		if got != want {
			t.Errorf("suffix %q: got %q", suffix, got)
		}
	}
}

// Review focus 1 for the token: a short file must fail closed.
func TestLoadOrCreateToken_RejectsShortFile(t *testing.T) {
	for _, content := range []string{"", "\n", "abc", strings.Repeat("a", 63) + "\n"} {
		path := filepath.Join(t.TempDir(), "setup-token")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadOrCreateToken(path)
		if err == nil {
			t.Fatalf("content %q accepted", content)
		}
		if !strings.Contains(err.Error(), "delete") {
			t.Errorf("error %q should tell the operator to delete the file", err)
		}
	}
}

// os.Link cannot be made to fail portably with a non-EEXIST error, so the
// message construction is tested through the helper the Link branch calls.
func TestLinkError_MentionsHardLinks(t *testing.T) {
	err := linkError("/x/jwt.key", errors.New("operation not permitted"))
	if !strings.Contains(err.Error(), "hard link") {
		t.Errorf("error %q should mention hard link support", err)
	}
	if !strings.Contains(err.Error(), "/x/jwt.key") {
		t.Errorf("error %q should name the path", err)
	}
}
