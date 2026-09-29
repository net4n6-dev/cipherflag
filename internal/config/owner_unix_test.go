//go:build unix

package config

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileOwner_ReportsTheOwnerOfAFile(t *testing.T) {
	path := writeConfig(t, savedSample)
	fi, err := os.Stat(path)
	require.NoError(t, err)

	uid, gid, ok := fileOwner(fi)
	require.True(t, ok)
	require.Equal(t, os.Getuid(), uid)
	st := fi.Sys().(*syscall.Stat_t)
	require.Equal(t, int(st.Gid), gid)
}

// The saved file and its backup keep the owner of the file they replace. As a
// non-root user this can only show the owner is unchanged (chown to the same
// owner is allowed); it cannot fail before the fix, which needs root and a
// file owned by someone else.
func TestSaveSections_KeepsTheOwnerOfTheFile(t *testing.T) {
	path := writeConfig(t, savedSample)
	before, err := os.Stat(path)
	require.NoError(t, err)
	wantUID, wantGID, _ := fileOwner(before)
	cfg := loadCfg(t, path)
	cfg.Sources.ZeekFile.PollIntervalSeconds = 45

	require.NoError(t, SaveSections(path, cfg, "sources.zeek_file"))

	for _, p := range []string{path, path + ".bak"} {
		fi, err := os.Stat(p)
		require.NoError(t, err)
		uid, gid, ok := fileOwner(fi)
		require.True(t, ok)
		require.Equal(t, wantUID, uid, p)
		require.Equal(t, wantGID, gid, p)
	}
}
