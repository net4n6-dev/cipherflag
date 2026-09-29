package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

const savedSample = `# CipherFlag Configuration (hand edited)

[server]
listen = "0.0.0.0:8443"  # keep this port

[storage]
postgres_url = "postgres://example.invalid/db"

# Zeek log reader.
[sources.zeek_file]
enabled = true
log_dir = "/var/log/zeek/current"

[analysis]
# Do not touch: tuned by hand.
recheck_interval_hours = 12
`

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cipherflag.toml")
	require.NoError(t, os.WriteFile(path, []byte(text), 0o644))
	return path
}

func loadCfg(t *testing.T, path string) *Config {
	t.Helper()
	cfg, err := Load(path)
	require.NoError(t, err)
	return cfg
}

// Everything outside the edited table survives byte for byte: comments, other
// tables, key order, and no defaults are written for keys the file never had.
func TestSaveSections_PreservesEverythingOutsideTheEditedTables(t *testing.T) {
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	require.NoError(t, SaveSections(path, cfg, "sources.zeek_file"))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(got)
	require.Contains(t, text, "# CipherFlag Configuration (hand edited)")
	require.Contains(t, text, `listen = "0.0.0.0:8443"  # keep this port`)
	require.Contains(t, text, "# Do not touch: tuned by hand.")
	require.Contains(t, text, "recheck_interval_hours = 12")
	require.Contains(t, text, "poll_interval_seconds = 45", "the edited table carries the new value")
	require.NotContains(t, text, "rank_formula", "no default keys the file never had")
	require.NotContains(t, text, "[ai]")
	require.NotContains(t, text, "[cbom]")
	require.Equal(t, 45, loadCfg(t, path).Sources.ZeekFile.PollIntervalSeconds)
	require.True(t, loadCfg(t, path).Sources.ZeekFile.Enabled, "unedited values of the table are kept")
}

func TestSaveSections_AppendsATableTheFileDoesNotHave(t *testing.T) {
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.Corelight.Enabled = true
	cfg.Sources.Corelight.APIURL = "https://corelight.example.test"

	require.NoError(t, SaveSections(path, cfg, "sources.corelight"))

	got, _ := os.ReadFile(path)
	require.True(t, strings.HasPrefix(string(got), savedSample), "the original text is kept and the table is added after it")
	require.Contains(t, string(got), "[sources.corelight]")
	require.Equal(t, "https://corelight.example.test", loadCfg(t, path).Sources.Corelight.APIURL)
}

func TestSaveSections_CreatesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.toml")
	cfg := &Config{}
	cfg.PCAP.MaxFileSizeMB = 500

	require.NoError(t, SaveSections(path, cfg, "pcap"))
	require.Equal(t, 500, loadCfg(t, path).PCAP.MaxFileSizeMB)
}

func TestSaveSections_KeepsTheOldFileAsABackup(t *testing.T) {
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	require.NoError(t, SaveSections(path, cfg, "sources.zeek_file"))

	bak, err := os.ReadFile(path + ".bak")
	require.NoError(t, err)
	require.Equal(t, savedSample, string(bak))
}

func TestSaveSections_NothingChangedWritesNothing(t *testing.T) {
	path := writeConfig(t, savedSample)
	require.NoError(t, SaveSections(path, loadCfg(t, path), "sources.zeek_file"))
	_, err := os.Stat(path + ".bak")
	require.True(t, os.IsNotExist(err), "an unchanged save leaves no backup")
}

// A file that defines the table in a form the patcher cannot rewrite (dotted
// keys at the root) would end up with the table defined twice. The save is
// refused with a message that says what to do, and the file is left exactly as
// it was.
func TestSaveSections_RefusesAFileItCannotPatch(t *testing.T) {
	text := "sources.corelight.enabled = true\n\n[storage]\npostgres_url = \"x\"\n"
	path := writeConfig(t, text)
	cfg := loadCfg(t, path)
	cfg.Sources.Corelight.APIURL = "https://corelight.example.test"

	err := SaveSections(path, cfg, "sources.corelight")
	require.Error(t, err)
	require.Contains(t, err.Error(), "by hand")
	got, _ := os.ReadFile(path)
	require.Equal(t, text, string(got), "the file is untouched")
	_, statErr := os.Stat(path + ".bak")
	require.True(t, os.IsNotExist(statErr))
}

func TestSaveSections_RejectsATableItDoesNotKnow(t *testing.T) {
	path := writeConfig(t, savedSample)
	require.Error(t, SaveSections(path, loadCfg(t, path), "analysis"))
}

// An unwritable config gives an actionable error and never a truncated file.
func TestSaveSections_ReadOnlyFileGivesAHelpfulError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45
	require.NoError(t, os.Chmod(path, 0o444))
	require.NoError(t, os.Chmod(filepath.Dir(path), 0o555))
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o755) })

	err := SaveSections(path, cfg, "sources.zeek_file")
	require.Error(t, err)
	require.Contains(t, err.Error(), "read-write")
	got, _ := os.ReadFile(path)
	require.Equal(t, savedSample, string(got))
}

// The shipped config: saving one table changes only that table's block.
func TestSaveSections_ShippedConfigChangesOnlyTheEditedTable(t *testing.T) {
	orig, err := os.ReadFile("../../config/cipherflag.toml")
	require.NoError(t, err)
	path := writeConfig(t, string(orig))
	cfg := loadCfg(t, path)
	cfg.Sources.Corelight.Enabled = true
	cfg.Sources.Corelight.APIURL = "https://corelight.example.test"

	require.NoError(t, SaveSections(path, cfg, "sources.corelight"))

	got, _ := os.ReadFile(path)
	// The shipped file already has [sources.corelight]: that block is rewritten
	// in place and every byte before and after it is kept.
	origText := string(orig)
	start := strings.Index(origText, "[sources.corelight]")
	end := strings.Index(origText, "[export.venafi]")
	require.True(t, start > 0 && end > start)
	require.True(t, strings.HasPrefix(string(got), origText[:start]), "text before the edited table is kept")
	require.True(t, strings.HasSuffix(string(got), origText[end:]), "text after the edited table is kept")
	require.Contains(t, string(got), "api_url = \"https://corelight.example.test\"")
	after := loadCfg(t, path)
	require.Equal(t, cfg.Sources.Corelight, after.Sources.Corelight)
	before := loadCfg(t, writeConfig(t, string(orig)))
	after.Sources.Corelight = before.Sources.Corelight
	require.Equal(t, before, after, "nothing else in the loaded config changed")
}

func injectSeams(t *testing.T) {
	t.Helper()
	origRename, origWrite := renameFile, writeTemp
	t.Cleanup(func() { renameFile, writeTemp = origRename, origWrite })
}

// A failing temp write (full disk) must not fall through to a truncating
// in-place write: the original file stays as it was.
func TestSaveSections_TempWriteFailureLeavesTheOriginalAlone(t *testing.T) {
	injectSeams(t)
	cause := errors.New("no space left on device")
	writeTemp = func(f *os.File, data []byte) error {
		_, _ = f.Write(data[:len(data)/2])
		return cause
	}
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	err := SaveSections(path, cfg, "sources.zeek_file")
	require.Error(t, err)
	require.ErrorIs(t, err, cause)
	got, _ := os.ReadFile(path)
	require.Equal(t, savedSample, string(got), "the original bytes remain")
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".cipherflag-"), "temp file %s left behind", e.Name())
	}
}

// Where the atomic rename is impossible (single-file bind mount) the save
// still succeeds through the in-place path.
func TestSaveSections_RenameFailureFallsBackToInPlaceWrite(t *testing.T) {
	injectSeams(t)
	renameFile = func(string, string) error { return errors.New("device or resource busy") }
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	require.NoError(t, SaveSections(path, cfg, "sources.zeek_file"))
	require.Equal(t, 45, loadCfg(t, path).Sources.ZeekFile.PollIntervalSeconds)
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".cipherflag-"), "temp file %s left behind", e.Name())
	}
}

// The in-place path truncates first, so it only runs when the previous
// content is safely backed up.
func TestSaveSections_BackupFailureBlocksTheInPlaceWrite(t *testing.T) {
	injectSeams(t)
	renameFile = func(string, string) error { return errors.New("device or resource busy") }
	path := writeConfig(t, savedSample)
	require.NoError(t, os.Mkdir(path+".bak", 0o755)) // the backup cannot be written
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	err := SaveSections(path, cfg, "sources.zeek_file")
	require.Error(t, err)
	require.Contains(t, err.Error(), "backed up")
	require.Contains(t, err.Error(), "by hand")
	got, _ := os.ReadFile(path)
	require.Equal(t, savedSample, string(got))
}

// A writable file in a read-only directory (no temp file, no backup possible)
// is refused, and the error carries the underlying cause.
func TestSaveSections_UnbackableInPlaceWriteErrorWrapsTheCause(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	path := writeConfig(t, savedSample)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45
	require.NoError(t, os.Chmod(filepath.Dir(path), 0o555))
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o755) })

	err := SaveSections(path, cfg, "sources.zeek_file")
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrPermission)
	got, _ := os.ReadFile(path)
	require.Equal(t, savedSample, string(got))
}

// A leftover .bak from an older save must not keep looser permissions than
// the config file: it holds the previous secrets.
func TestSaveSections_BackupIsNeverLooserThanTheConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	path := writeConfig(t, savedSample)
	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path+".bak", []byte("old"), 0o644))
	require.NoError(t, os.Chmod(path+".bak", 0o644))
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	require.NoError(t, SaveSections(path, cfg, "sources.zeek_file"))

	fi, err := os.Stat(path + ".bak")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o600), fi.Mode().Perm())
	bak, _ := os.ReadFile(path + ".bak")
	require.Equal(t, savedSample, string(bak))
}

// Two saves of different tables from separate handlers must both survive.
func TestSaveSections_ConcurrentSavesOfDifferentTablesKeepBoth(t *testing.T) {
	for i := 0; i < 40; i++ {
		path := writeConfig(t, savedSample)
		a, b := loadCfg(t, path), loadCfg(t, path)
		a.PCAP.MaxFileSizeMB = 600 + i
		b.Sources.ZeekFile.PollIntervalSeconds = 100 + i

		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); errs <- SaveSections(path, a, "pcap") }()
		go func() { defer wg.Done(); errs <- SaveSections(path, b, "sources.zeek_file") }()
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		got := loadCfg(t, path)
		require.Equal(t, 600+i, got.PCAP.MaxFileSizeMB, "iteration %d lost the pcap save", i)
		require.Equal(t, 100+i, got.Sources.ZeekFile.PollIntervalSeconds, "iteration %d lost the zeek save", i)
	}
}

// A block the header scanner cannot see into (a quoted table name containing
// a bracket) would be dropped silently by a replace; the whole-file check
// refuses it.
func TestSaveSections_RefusesToDropATableOutsideThePatchedOnes(t *testing.T) {
	text := "[sources.corelight]\nenabled = true\n['odd]name']\nfoo = 1\n"
	path := writeConfig(t, text)
	cfg := loadCfg(t, path)
	cfg.Sources.Corelight.APIURL = "https://corelight.example.test"

	err := SaveSections(path, cfg, "sources.corelight")
	require.Error(t, err)
	require.Contains(t, err.Error(), "by hand")
	got, _ := os.ReadFile(path)
	require.Equal(t, text, string(got))
}

func TestSaveSections_KeepsASymlinkedConfigASymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.toml")
	require.NoError(t, os.WriteFile(real, []byte(savedSample), 0o644))
	link := filepath.Join(dir, "link.toml")
	require.NoError(t, os.Symlink(real, link))
	cfg := loadCfg(t, link)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	require.NoError(t, SaveSections(link, cfg, "sources.zeek_file"))

	fi, err := os.Lstat(link)
	require.NoError(t, err)
	require.True(t, fi.Mode()&os.ModeSymlink != 0, "the symlink is still a symlink")
	require.Equal(t, 45, loadCfg(t, real).Sources.ZeekFile.PollIntervalSeconds)
	_, err = os.Stat(real + ".bak")
	require.NoError(t, err, "the backup sits next to the real file")
}

// rename ignores the file's own permissions, so a read-only config in a
// writable directory must be refused up front.
func TestSaveSections_ReadOnlyFileInWritableDirIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	path := writeConfig(t, savedSample)
	require.NoError(t, os.Chmod(path, 0o444))
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	err := SaveSections(path, cfg, "sources.zeek_file")
	require.Error(t, err)
	require.Contains(t, err.Error(), "read-write")
	got, _ := os.ReadFile(path)
	require.Equal(t, savedSample, string(got))
	_, statErr := os.Stat(path + ".bak")
	require.True(t, os.IsNotExist(statErr))
}
