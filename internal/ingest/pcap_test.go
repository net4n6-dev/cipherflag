package ingest

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestFindCompletedPCAPJobs(t *testing.T) {
	dir := t.TempDir()

	// Create three job directories: two completed and one incomplete.
	for _, name := range []string{"job-001", "job-002", "job-003"} {
		jobDir := filepath.Join(dir, name)
		if err := os.MkdirAll(jobDir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Place .done sentinel in job-001 and job-003 only.
	for _, name := range []string{"job-001", "job-003"} {
		sentinel := filepath.Join(dir, name, ".done")
		if err := os.WriteFile(sentinel, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}

	completed := FindCompletedPCAPJobs(dir)
	sort.Strings(completed)

	if len(completed) != 2 {
		t.Fatalf("expected 2 completed jobs, got %d: %v", len(completed), completed)
	}
	if completed[0] != "job-001" {
		t.Errorf("expected job-001, got %s", completed[0])
	}
	if completed[1] != "job-003" {
		t.Errorf("expected job-003, got %s", completed[1])
	}
}

func TestFindCompletedPCAPJobs_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	completed := FindCompletedPCAPJobs(dir)
	if len(completed) != 0 {
		t.Fatalf("expected 0 completed jobs in empty dir, got %d", len(completed))
	}
}

func TestFindCompletedPCAPJobs_NonexistentDir(t *testing.T) {
	completed := FindCompletedPCAPJobs("/nonexistent/pcap/dir")
	if completed != nil {
		t.Fatalf("expected nil for nonexistent dir, got %v", completed)
	}
}

func TestFindCompletedPCAPJobs_IgnoresFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a regular file (not a directory) — should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "not-a-job.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create one valid completed job.
	jobDir := filepath.Join(dir, "job-valid")
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, ".done"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	completed := FindCompletedPCAPJobs(dir)
	if len(completed) != 1 {
		t.Fatalf("expected 1 completed job, got %d: %v", len(completed), completed)
	}
	if completed[0] != "job-valid" {
		t.Errorf("expected job-valid, got %s", completed[0])
	}
}
