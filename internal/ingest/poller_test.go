package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLogEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")

	content := `# This is a comment
{"ts":1234567890.0,"fingerprint":"abc123","certificate.subject":"CN=test"}
{"ts":1234567891.0,"fingerprint":"def456","certificate.subject":"CN=test2"}

# Another comment
{"ts":1234567892.0,"fingerprint":"ghi789","certificate.subject":"CN=test3"}
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	entries, offset, err := ReadLogEntries(path, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if offset == 0 {
		t.Fatal("expected non-zero offset")
	}

	// Verify that entries are actual JSON lines (not comments or blanks).
	for i, e := range entries {
		if e[0] != '{' {
			t.Errorf("entry %d does not start with '{': %s", i, string(e))
		}
	}
}

func TestReadLogEntries_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")

	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	entries, offset, err := ReadLogEntries(path, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
	if offset != 0 {
		t.Fatalf("expected offset 0 for empty file, got %d", offset)
	}
}

func TestReadLogEntries_MissingFile(t *testing.T) {
	entries, offset, err := ReadLogEntries("/nonexistent/path/x509.log", 0)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries for missing file, got %d", len(entries))
	}
	if offset != 0 {
		t.Fatalf("expected offset 0 for missing file, got %d", offset)
	}
}

func TestReadLogEntries_FromOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")

	line1 := `{"ts":1234567890.0,"fingerprint":"abc123"}` + "\n"
	line2 := `{"ts":1234567891.0,"fingerprint":"def456"}` + "\n"
	content := line1 + line2

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Read first pass to get offset after line1.
	entries1, offset1, err := ReadLogEntries(path, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries1) != 2 {
		t.Fatalf("expected 2 entries on first read, got %d", len(entries1))
	}

	// Append a third line.
	line3 := `{"ts":1234567892.0,"fingerprint":"ghi789"}` + "\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line3); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	// Read from offset — should only see the third line.
	entries2, offset2, err := ReadLogEntries(path, offset1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries2) != 1 {
		t.Fatalf("expected 1 entry from offset, got %d", len(entries2))
	}
	if offset2 <= offset1 {
		t.Fatalf("expected offset to advance, got %d <= %d", offset2, offset1)
	}

	// Verify it is the third entry.
	if string(entries2[0]) != `{"ts":1234567892.0,"fingerprint":"ghi789"}` {
		t.Errorf("unexpected entry content: %s", string(entries2[0]))
	}
}
