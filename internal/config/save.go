// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
)

// tableHeader matches a TOML table header line, [a.b] or [[a.b]], with an
// optional trailing comment.
var tableHeader = regexp.MustCompile(`^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(#.*)?$`)

// block is a header line and the lines up to the next header. The text before
// the first header is a block with an empty name.
type block struct {
	name  string
	lines []string
}

func splitBlocks(text string) []block {
	blocks := []block{{}}
	for _, line := range strings.SplitAfter(text, "\n") {
		if line == "" {
			continue
		}
		if m := tableHeader.FindStringSubmatch(strings.TrimRight(line, "\r\n")); m != nil {
			blocks = append(blocks, block{name: strings.ReplaceAll(m[1], " ", "")})
		}
		last := &blocks[len(blocks)-1]
		last.lines = append(last.lines, line)
	}
	return blocks
}

// sectionValue returns the part of cfg a Settings table maps to.
func sectionValue(cfg *Config, table string) (any, error) {
	switch table {
	case "sources.zeek_file":
		return cfg.Sources.ZeekFile, nil
	case "sources.corelight":
		return cfg.Sources.Corelight, nil
	case "pcap":
		return cfg.PCAP, nil
	case "export.venafi":
		return cfg.Export.Venafi, nil
	}
	return nil, fmt.Errorf("config: Settings cannot save table [%s]", table)
}

// wantedSection returns the table's value from cfg after the defaulting Load
// applies, so it can be compared with what a file loads to.
func wantedSection(cfg *Config, table string) (any, error) {
	v, err := sectionValue(cfg, table)
	if err != nil {
		return nil, err
	}
	enc, err := encodeTable(table, v)
	if err != nil {
		return nil, err
	}
	loaded, err := parseConfigText(enc)
	if err != nil {
		return nil, err
	}
	return sectionValue(loaded, table)
}

// nestedMap wraps v under the dotted table path, so the encoder emits a header
// with the full path.
func nestedMap(table string, v any) map[string]any {
	parts := strings.Split(table, ".")
	out := map[string]any{parts[len(parts)-1]: v}
	for i := len(parts) - 2; i >= 0; i-- {
		out = map[string]any{parts[i]: out}
	}
	return out
}

// encodeTable returns the text of one table, header included and children of
// no interest excluded.
func encodeTable(table string, v any) (string, error) {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(nestedMap(table, v)); err != nil {
		return "", err
	}
	for _, b := range splitBlocks(buf.String()) {
		if b.name == table {
			return strings.Join(b.lines, ""), nil
		}
	}
	return "", fmt.Errorf("config: could not encode table [%s]", table)
}

// trailingBlankAndComments returns the run of blank and comment-only lines at
// the end of a block's lines.
func trailingBlankAndComments(lines []string) []string {
	i := len(lines)
	for i > 1 {
		t := strings.TrimSpace(lines[i-1])
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		i--
	}
	return lines[i:]
}

// patchTables replaces (or appends) the named tables in text.
func patchTables(text string, cfg *Config, tables []string) (string, error) {
	blocks := splitBlocks(text)
	var appended []string
	for _, table := range tables {
		v, err := sectionValue(cfg, table)
		if err != nil {
			return "", err
		}
		enc, err := encodeTable(table, v)
		if err != nil {
			return "", err
		}
		enc = strings.TrimRight(enc, "\n") + "\n"
		replaced := false
		for i := range blocks {
			if blocks[i].name == table && i > 0 {
				// Blank and comment lines at the end of a block belong to
				// whatever follows it; keep them where they are.
				blocks[i].lines = append([]string{enc}, trailingBlankAndComments(blocks[i].lines)...)
				replaced = true
				break
			}
		}
		if !replaced {
			appended = append(appended, enc)
		}
	}
	var out strings.Builder
	for _, b := range blocks {
		out.WriteString(strings.Join(b.lines, ""))
	}
	for _, enc := range appended {
		// Separate an appended table from the text before it by one blank line.
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteString("\n")
		}
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n\n") {
			out.WriteString("\n")
		}
		out.WriteString(enc)
	}
	return out.String(), nil
}

// saveMu serialises SaveSections: it holds from reading the file through
// writing it, so two saves of different tables (Settings > Sources and
// Settings > Venafi are separate handlers) cannot lose each other's update.
var saveMu sync.Mutex

// SaveSections writes the Settings-edited tables of cfg into the file at path
// and leaves the rest of the file exactly as it is (comments, other tables,
// key order). A table is patched only when the file's own value for it differs
// from what cfg holds. The new text is checked before anything is written: it
// must parse and each patched table must decode to what cfg holds, otherwise
// the file is left untouched and the error says to edit it by hand. The
// previous content is kept in path+".bak". Only "sources.zeek_file",
// "sources.corelight", "pcap" and "export.venafi" can be saved.
func SaveSections(path string, cfg *Config, tables ...string) error {
	saveMu.Lock()
	defer saveMu.Unlock()
	// A symlinked config stays a symlink: everything happens on its target.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	// A file that does not exist yet is created, even for values equal to the
	// defaults.
	missing := err != nil
	current, err := parseConfigText(string(old))
	if err != nil {
		return fmt.Errorf("config file %s does not load (%v); edit it by hand", path, err)
	}
	var changed []string
	for _, table := range tables {
		want, err := wantedSection(cfg, table)
		if err != nil {
			return err
		}
		have, _ := sectionValue(current, table)
		if missing || !reflect.DeepEqual(want, have) {
			changed = append(changed, table)
		}
	}
	if len(changed) == 0 {
		return nil // nothing the file does not already say
	}
	text, err := patchTables(string(old), cfg, changed)
	if err != nil {
		return err
	}
	if err := verifyPatched(string(old), text, cfg, changed); err != nil {
		return fmt.Errorf("%w; edit %s by hand", err, path)
	}
	mode := fs.FileMode(0o644)
	var ref os.FileInfo // the existing file, whose owner the new files copy
	if fi, err := os.Stat(path); err == nil {
		ref = fi
		mode = fi.Mode().Perm()
		// rename ignores the file's own permissions, so check them here: a
		// read-only config (or read-only single-file mount) must not be replaced.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return notWritable(path, err)
		}
		_ = f.Close()
	}
	var backupErr error
	if len(old) > 0 {
		if backupErr = writeBackup(path+".bak", old, mode); backupErr != nil {
			log.Warn().Err(backupErr).Str("path", path+".bak").Msg("config: could not keep a backup of the previous file")
		} else {
			copyOwner(path+".bak", ref)
		}
	}
	return writeConfigFile(path, []byte(text), mode, backupErr, ref)
}

// copyOwner gives name the owner and group of ref, so a file CipherFlag
// creates (running as root in the container) does not change who owns the
// operator's config on a bind-mounted host directory. Best effort: an
// unprivileged process may not be allowed to, and that is fine.
func copyOwner(name string, ref os.FileInfo) {
	if ref == nil {
		return
	}
	if uid, gid, ok := fileOwner(ref); ok {
		_ = os.Chown(name, uid, gid)
	}
}

// writeBackup writes data to bak readable only by its owner while it is
// written, then gives it the mode of the config itself, so a leftover backup
// with looser permissions never holds the previous secrets.
func writeBackup(bak string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(bak, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(bak, mode)
}

func notWritable(path string, cause error) error {
	return fmt.Errorf("config file %s is not writable: mount its directory read-write, or edit the file by hand: %w", path, cause)
}

// verifyPatched checks that text loads, that every patched table comes back as
// the value cfg holds, and that nothing else changed: with the patched tables
// removed, the old and the new text must decode to the same document.
func verifyPatched(old, text string, cfg *Config, tables []string) error {
	loaded, err := parseConfigText(text)
	if err != nil {
		return fmt.Errorf("the config file defines a Settings table in a form that cannot be rewritten (%v)", err)
	}
	for _, table := range tables {
		want, _ := wantedSection(cfg, table)
		got, _ := sectionValue(loaded, table)
		if !reflect.DeepEqual(want, got) {
			return fmt.Errorf("the config file defines table [%s] in a form that cannot be rewritten", table)
		}
	}
	var before, after map[string]any
	if _, err := toml.Decode(old, &before); err != nil {
		return fmt.Errorf("the config file cannot be checked before rewriting (%v)", err)
	}
	if _, err := toml.Decode(text, &after); err != nil {
		return fmt.Errorf("the config file cannot be checked after rewriting (%v)", err)
	}
	for _, table := range tables {
		removeTable(before, strings.Split(table, "."))
		removeTable(after, strings.Split(table, "."))
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("rewriting the Settings tables would change other parts of the config file")
	}
	return nil
}

// removeTable deletes the table at path from m and prunes parent tables that
// become empty.
func removeTable(m map[string]any, path []string) {
	if m == nil {
		return
	}
	if len(path) == 1 {
		delete(m, path[0])
		return
	}
	child, ok := m[path[0]].(map[string]any)
	if !ok {
		return
	}
	removeTable(child, path[1:])
	if len(child) == 0 {
		delete(m, path[0])
	}
}

// Seams for tests to inject write failures.
var (
	renameFile = os.Rename
	writeTemp  = func(f *os.File, data []byte) error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Sync()
	}
)

// writeConfigFile replaces path with data: atomically when the directory
// allows it, in place when it does not (a single-file bind mount cannot be
// renamed over), and with an actionable error when neither works.
//
// The in-place write truncates first, so it is used only when no temp file
// could be created or the final rename failed, never after a failed temp
// write (a full disk would cut the file short), and never when the previous
// content should have been backed up (backupErr) and was not.
func writeConfigFile(path string, data []byte, mode fs.FileMode, backupErr error, ref os.FileInfo) error {
	dir := filepath.Dir(path)
	var cause error
	tmp, err := os.CreateTemp(dir, ".cipherflag-*.toml")
	if err == nil {
		name := tmp.Name()
		fail := func(err error) error {
			_ = tmp.Close()
			_ = os.Remove(name)
			return err
		}
		if err := writeTemp(tmp, data); err != nil {
			return fail(fmt.Errorf("write %s: %w", name, err))
		}
		if err := tmp.Close(); err != nil {
			return fail(fmt.Errorf("write %s: %w", name, err))
		}
		copyOwner(name, ref)
		if err := os.Chmod(name, mode); err != nil {
			return fail(fmt.Errorf("write %s: %w", name, err))
		}
		if err := renameFile(name, path); err == nil {
			return nil
		} else {
			cause = err
			_ = os.Remove(name)
		}
	} else {
		cause = err
	}
	if backupErr != nil {
		return fmt.Errorf("config file %s cannot be replaced atomically (%v) and the previous file could not be backed up (%w); edit it by hand", path, cause, backupErr)
	}
	mkErr := os.MkdirAll(dir, 0o755)
	if mkErr == nil {
		if werr := os.WriteFile(path, data, mode); werr == nil {
			return nil
		} else {
			return notWritable(path, errors.Join(cause, werr))
		}
	}
	return notWritable(path, errors.Join(cause, mkErr))
}
