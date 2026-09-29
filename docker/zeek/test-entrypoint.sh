#!/bin/sh
# Hermetic tests of docker/zeek/sensor-lib.sh with a stub `zeek`; needs no
# Docker and runs on Linux and macOS.
# Usage: docker/zeek/test-entrypoint.sh   (exits non-zero on failure)
# The `set -e` cases start a child shell named by TEST_SH (default sh), so
# `TEST_SH=dash dash docker/zeek/test-entrypoint.sh` runs everything in dash.
set -u
TEST_SH="${TEST_SH:-sh}"

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

# A stub zeek: `zeek -r <pcap> <site script>` counts the call, fails when the
# capture's content says "broken", and otherwise writes the two logs the
# poller reads into the current directory.
mkdir -p "$work/bin"
cat > "$work/bin/zeek" <<'STUB'
#!/bin/sh
echo "$2" >> "$STUB_CALLS"
case "$(cat "$2")" in
    *broken*) exit 1 ;;
esac
echo '{}' > x509.log
echo '{}' > ssl.log
STUB
chmod +x "$work/bin/zeek"
PATH="$work/bin:$PATH"

old=202001010000 # a fixed old timestamp for touch -t

# newenv builds a fresh sensor environment and (re)sources the library.
newenv() {
    env_dir=$(mktemp -d "$work/env.XXXXXX")
    LOG_DIR="$env_dir/logs"
    PCAP_DIR="$env_dir/pcap"
    STATE_DIR="$LOG_DIR/.state"
    STUB_CALLS="$env_dir/calls"
    export STUB_CALLS
    : > "$STUB_CALLS"
    mkdir -p "$LOG_DIR" "$PCAP_DIR"
    PCAP_SETTLE_SECONDS=0
    WAITING_FOR=""
    FAILED_LOGGED=""
    SETTLE_WARNED=""
    RETENTION_WARNED=""
    # shellcheck disable=SC1091
    . "$here/sensor-lib.sh"
}
calls() { wc -l < "$STUB_CALLS" | tr -d ' '; }

# 1. One capture: the layout older sensors used is unchanged, and the
#    durable marker exists.
newenv
mkdir "$PCAP_DIR/job1"; echo ok > "$PCAP_DIR/job1/a.pcap"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job1/.done" ] && [ -f "$LOG_DIR/job1/x509.log" ] || fail "single capture: logs and .done belong in <logs>/<job>"
[ -f "$STATE_DIR/job1/a.pcap" ] || fail "single capture: no durable marker"

# 2. ce:0010: deleting the finished job's logs must not make the sensor run
#    the capture again.
rm -rf "$LOG_DIR/job1"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 1 ] || fail "deleted job logs: the capture was processed again ($(calls) runs)"
[ ! -e "$LOG_DIR/job1" ] || fail "deleted job logs: the log directory came back"

# 3. ce:0009: several captures in one job are all processed, each into its
#    own log directory named after the file, and a rescan does nothing.
newenv
mkdir "$PCAP_DIR/job3"; echo ok > "$PCAP_DIR/job3/a.pcap"; echo ok > "$PCAP_DIR/job3/b.pcapng"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job3--a.pcap/.done" ] || fail "multi capture: job3--a.pcap not done"
[ -f "$LOG_DIR/job3--b.pcapng/.done" ] || fail "multi capture: job3--b.pcapng not done"
[ "$(calls)" -eq 2 ] || fail "multi capture: expected 2 runs, got $(calls)"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 2 ] || fail "multi capture: a rescan ran Zeek again"

# 4. A failing capture does not block its siblings and is not retried.
newenv
mkdir "$PCAP_DIR/job4"; echo ok > "$PCAP_DIR/job4/a.pcap"; echo broken > "$PCAP_DIR/job4/b.pcap"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job4--a.pcap/.done" ] || fail "failure isolation: the good capture was not processed"
[ -f "$LOG_DIR/job4--b.pcap/.failed" ] && [ ! -f "$LOG_DIR/job4--b.pcap/.done" ] || fail "failure isolation: the broken capture must be .failed only"
[ "$(cat "$LOG_DIR/job4--b.pcap/.failed")" = "exit status 1" ] || fail "failure isolation: .failed must hold the exit status"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 2 ] || fail "failure isolation: the failed capture was retried"

# 5. Upgrade: markers an older sensor left in the log directory are honoured.
newenv
mkdir "$PCAP_DIR/job5" "$PCAP_DIR/job5b" "$LOG_DIR/job5" "$LOG_DIR/job5b"
echo ok > "$PCAP_DIR/job5/a.pcap"; echo ok > "$PCAP_DIR/job5b/a.pcap"
touch "$LOG_DIR/job5/.done"; echo "exit status 1" > "$LOG_DIR/job5b/.failed"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 0 ] || fail "legacy markers: a capture already marked by an older sensor was processed"
[ -f "$STATE_DIR/job5/a.pcap" ] && [ -f "$STATE_DIR/job5b/a.pcap" ] || fail "legacy markers: no durable marker was made"

# 6. ce:0011: a capture that is still changing waits, and the wait is
#    logged once; a capture moved into place (old mtime) is processed.
newenv
PCAP_SETTLE_SECONDS=10
mkdir "$PCAP_DIR/job6"; echo ok > "$PCAP_DIR/job6/copying.pcap"
scan_once > "$env_dir/out" 2>&1; scan_once >> "$env_dir/out" 2>&1
[ "$(calls)" -eq 0 ] || fail "settle: a capture written just now was processed"
[ ! -e "$LOG_DIR/job6" ] && [ ! -e "$STATE_DIR/job6" ] || fail "settle: a waiting capture must leave no trace"
[ "$(grep -c 'Waiting for' "$env_dir/out")" -eq 1 ] || fail "settle: the wait must be logged once, not on every scan"
touch -t "$old" "$PCAP_DIR/job6/copying.pcap"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job6/.done" ] || fail "settle: a capture with an old mtime was not processed"

# 7. Names with spaces.
newenv
mkdir "$PCAP_DIR/my job"; echo ok > "$PCAP_DIR/my job/a b.pcap"; echo ok > "$PCAP_DIR/my job/c d.pcap"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/my job--a b.pcap/.done" ] && [ -f "$LOG_DIR/my job--c d.pcap/.done" ] || fail "names with spaces: not processed"
[ -f "$STATE_DIR/my job/a b.pcap" ] || fail "names with spaces: no durable marker"

# 8. a.pcap and a.pcapng never share a log directory, and a
#    job named x--y does not collide with capture y of job x.
newenv
mkdir "$PCAP_DIR/job8"; echo ok > "$PCAP_DIR/job8/a.pcap"; echo ok > "$PCAP_DIR/job8/a.pcapng"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job8--a.pcap/.done" ] && [ -f "$LOG_DIR/job8--a.pcapng/.done" ] || fail "same stem: both captures need their own directory"
newenv
mkdir "$PCAP_DIR/x" "$PCAP_DIR/x--y.pcap"
echo ok > "$PCAP_DIR/x/y.pcap"; echo ok > "$PCAP_DIR/x/z.pcap"; echo ok > "$PCAP_DIR/x--y.pcap/q.pcap"
scan_once > "$env_dir/out" 2>&1
# job x holds two captures (y.pcap, z.pcap): logs in "x--y.pcap" and "x--z.pcap";
# job "x--y.pcap" holds one capture: logs in "x--y.pcap": the same directory.
[ "$(calls)" -eq 2 ] || fail "collision: exactly one of the colliding captures may run (got $(calls))"
grep -q "collides" "$STATE_DIR"/*/* 2>/dev/null || fail "collision: the refused capture must be marked with the reason"

# 9. A second capture added to an already processed single-capture job:
#    only the new one runs (into <job>--<file>), the old logs stay.
newenv
mkdir "$PCAP_DIR/job9"; echo ok > "$PCAP_DIR/job9/a.pcap"
scan_once > "$env_dir/out" 2>&1
echo ok > "$PCAP_DIR/job9/b.pcap"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 2 ] || fail "added capture: expected 2 runs in total, got $(calls)"
[ -f "$LOG_DIR/job9/.done" ] && [ -f "$LOG_DIR/job9--b.pcap/.done" ] || fail "added capture: the old logs stay and the new capture gets its own directory"

# 10. A write failure must not kill the watcher. The watcher runs under
#     `set -e` in the entrypoint, so scan_once is run that way here (the
#     harness itself is not under -e).
# 10a. A state directory that cannot be written: the capture is skipped,
#      reported once per process (two scans in one shell), left unmarked so it
#      is retried, and a later capture in another job is still processed.
if [ "$(id -u)" -eq 0 ]; then
    echo "skip: test 10a needs a non-root user (root ignores chmod)"
else
    newenv
    mkdir "$PCAP_DIR/a10" "$PCAP_DIR/b10" "$STATE_DIR" "$STATE_DIR/b10"
    echo ok > "$PCAP_DIR/a10/a.pcap"; echo ok > "$PCAP_DIR/b10/b.pcap"
    chmod 555 "$STATE_DIR"
    ( set -e; scan_once; scan_once ) > "$env_dir/out" 2>&1
    rc=$?
    chmod 755 "$STATE_DIR"
    [ "$rc" -eq 0 ] || fail "unwritable state: the scan died under set -e (status $rc)"
    [ -f "$LOG_DIR/b10/.done" ] || fail "unwritable state: a later, healthy capture was not processed"
    [ "$(grep -c 'FAILED PCAP.*cannot create' "$env_dir/out")" -eq 1 ] || fail "unwritable state: the failure must be logged once per process"
    [ ! -e "$STATE_DIR/a10" ] || fail "unwritable state: a transient failure must not leave a marker"
fi
# 10b. A log directory name over NAME_MAX can never be created: the capture
#      is marked failed with the reason and the scan carries on.
newenv
long="$(printf '%0245d' 0).pcap"
mkdir "$PCAP_DIR/j10" "$PCAP_DIR/z10"
echo ok > "$PCAP_DIR/j10/$long"; echo ok > "$PCAP_DIR/j10/short.pcap"; echo ok > "$PCAP_DIR/z10/ok.pcap"
( set -e; scan_once ) > "$env_dir/out" 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "long name: the scan died under set -e (status $rc)"
[ -f "$LOG_DIR/z10/.done" ] || fail "long name: a later, healthy capture was not processed"
[ -f "$LOG_DIR/j10--short.pcap/.done" ] || fail "long name: the short sibling was not processed"
grep -q "too long" "$STATE_DIR/j10/$long" 2>/dev/null || fail "long name: the capture must be marked failed with the reason"
grep -q "name too long" "$env_dir/out" || fail "long name: the refusal must be logged"

# 11. An idle scan must not glob the job directory for captures that already
#     have a marker (that made idle scans quadratic in the job size).
newenv
mkdir "$PCAP_DIR/job11"; echo ok > "$PCAP_DIR/job11/a.pcap"; echo ok > "$PCAP_DIR/job11/b.pcap"
scan_once > "$env_dir/out" 2>&1
captures_in() { echo x >> "$env_dir/ci"; echo 2; }
: > "$env_dir/ci"
scan_once > "$env_dir/out" 2>&1
[ "$(wc -l < "$env_dir/ci" | tr -d ' ')" -eq 0 ] || fail "idle scan: captures_in ran for captures that already have a marker"

# 12. Legacy markers only cover the one-capture layout: a job that an older
#     sensor processed (first capture only) and that now holds two captures
#     runs both into <job>--<file>, and the legacy directory is left alone.
newenv
mkdir "$PCAP_DIR/job12" "$LOG_DIR/job12"
echo ok > "$PCAP_DIR/job12/a.pcap"; echo ok > "$PCAP_DIR/job12/b.pcap"
touch "$LOG_DIR/job12/.done"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job12--a.pcap/.done" ] && [ -f "$LOG_DIR/job12--b.pcap/.done" ] || fail "legacy multi capture: both captures run into their own directories"
[ "$(calls)" -eq 2 ] || fail "legacy multi capture: expected 2 runs, got $(calls)"
[ ! -e "$LOG_DIR/job12/x509.log" ] || fail "legacy multi capture: the legacy directory must be left alone"

# 13. PCAP_SETTLE_SECONDS that is not a whole number falls back to 10 (with
#     one warning) instead of waiting forever.
newenv
mkdir "$PCAP_DIR/job13" "$PCAP_DIR/job13b"
echo ok > "$PCAP_DIR/job13/fresh.pcap"; echo ok > "$PCAP_DIR/job13b/old.pcap"
touch -t "$old" "$PCAP_DIR/job13b/old.pcap"
PCAP_SETTLE_SECONDS=10s
scan_once > "$env_dir/out" 2>&1; scan_once >> "$env_dir/out" 2>&1
[ ! -e "$LOG_DIR/job13" ] || fail "bad settle value: a fresh capture must still wait"
[ -f "$LOG_DIR/job13b/.done" ] || fail "bad settle value: an old capture must be processed"
[ "$(grep -c 'PCAP_SETTLE_SECONDS' "$env_dir/out")" -eq 1 ] || fail "bad settle value: expected exactly one warning"

# 14. A symlinked capture is judged by its target's mtime.
newenv
PCAP_SETTLE_SECONDS=10
echo ok > "$env_dir/real.pcap"; touch -t "$old" "$env_dir/real.pcap"
mkdir "$PCAP_DIR/job14"; ln -s "$env_dir/real.pcap" "$PCAP_DIR/job14/link.pcap"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/job14/.done" ] || fail "symlink: a link to a settled file was not processed"

# 15. Glob characters in job and capture names.
newenv
mkdir "$PCAP_DIR/j[a]*"; echo ok > "$PCAP_DIR/j[a]*/c?.pcap"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/j[a]*/.done" ] && [ -f "$STATE_DIR/j[a]*/c?.pcap" ] || fail "glob characters: not processed with the right markers"
[ "$(calls)" -eq 1 ] || fail "glob characters: expected 1 run, got $(calls)"

# 16. ce:0012: retention deletes old rotated logs of every type and old
#     finished job directories, and nothing else.
newenv
ZEEK_LOG_RETENTION_HOURS=1
touch "$LOG_DIR/x509.log" "$LOG_DIR/conn.log"
touch "$LOG_DIR/x509.2026-01-01-01-00-00.log" "$LOG_DIR/conn.2026-01-01-01-00-00.log" "$LOG_DIR/dns.2026-01-01-01-00-00.log.gz"
touch -t "$old" "$LOG_DIR/x509.2026-01-01-01-00-00.log" "$LOG_DIR/conn.2026-01-01-01-00-00.log" "$LOG_DIR/dns.2026-01-01-01-00-00.log.gz"
touch "$LOG_DIR/ssl.2026-09-28-17-00-00.log"   # a fresh rotated log
mkdir "$LOG_DIR/oldjob" "$LOG_DIR/youngjob" "$LOG_DIR/failedold" "$LOG_DIR/runningjob" "$STATE_DIR"
touch "$LOG_DIR/oldjob/.done" "$LOG_DIR/oldjob/x509.log"
touch -t "$old" "$LOG_DIR/oldjob/.done"
touch "$LOG_DIR/youngjob/.done"
echo "exit status 1" > "$LOG_DIR/failedold/.failed"; touch -t "$old" "$LOG_DIR/failedold/.failed"
touch "$LOG_DIR/runningjob/x509.log"; touch -t "$old" "$LOG_DIR/runningjob/x509.log" # no marker: in progress
# dot directories, rotated-looking files inside a job directory, and a
# symlinked rotated log must all survive (maxdepth 1, type f, no dot globs).
mkdir "$LOG_DIR/.hidden"; touch "$LOG_DIR/.hidden/.done" "$LOG_DIR/.hidden/keep"; touch -t "$old" "$LOG_DIR/.hidden/.done" "$LOG_DIR/.hidden/keep"
touch "$STATE_DIR/.done" "$STATE_DIR/oldfile"; touch -t "$old" "$STATE_DIR/.done" "$STATE_DIR/oldfile"
touch "$LOG_DIR/youngjob/x509.2026-01-01-01-00-00.log"; touch -t "$old" "$LOG_DIR/youngjob/x509.2026-01-01-01-00-00.log"
echo t > "$env_dir/target.log"; touch -t "$old" "$env_dir/target.log"; ln -s "$env_dir/target.log" "$LOG_DIR/ssl.2026-01-01-01-00-00.log"
retention_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/.hidden/.done" ] && [ -f "$LOG_DIR/.hidden/keep" ] || fail "retention: dot directories must never be candidates"
[ -f "$STATE_DIR/.done" ] && [ -f "$STATE_DIR/oldfile" ] || fail "retention: files in the state directory must stay"
[ -f "$LOG_DIR/youngjob/x509.2026-01-01-01-00-00.log" ] || fail "retention: rotated-looking files inside a job directory must stay"
[ -L "$LOG_DIR/ssl.2026-01-01-01-00-00.log" ] && [ -f "$env_dir/target.log" ] || fail "retention: a symlinked rotated log must stay"
[ ! -e "$LOG_DIR/x509.2026-01-01-01-00-00.log" ] && [ ! -e "$LOG_DIR/conn.2026-01-01-01-00-00.log" ] && [ ! -e "$LOG_DIR/dns.2026-01-01-01-00-00.log.gz" ] || fail "retention: old rotated logs of every type must go"
[ -f "$LOG_DIR/x509.log" ] && [ -f "$LOG_DIR/conn.log" ] || fail "retention: the live logs must stay"
[ -f "$LOG_DIR/ssl.2026-09-28-17-00-00.log" ] || fail "retention: a fresh rotated log must stay"
[ ! -e "$LOG_DIR/oldjob" ] && [ ! -e "$LOG_DIR/failedold" ] || fail "retention: old finished job directories (.done and .failed) must go"
[ -d "$LOG_DIR/youngjob" ] || fail "retention: a recently finished job directory must stay"
[ -d "$LOG_DIR/runningjob" ] || fail "retention: a job directory without a marker (in progress) must never be removed"
[ -d "$STATE_DIR" ] || fail "retention: the state directory must never be removed"

# 17. Retention 0 disables it; a garbage value warns once and disables it.
newenv
ZEEK_LOG_RETENTION_HOURS=0
touch "$LOG_DIR/x509.2026-01-01-01-00-00.log"; touch -t "$old" "$LOG_DIR/x509.2026-01-01-01-00-00.log"
retention_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/x509.2026-01-01-01-00-00.log" ] || fail "retention 0 must keep everything"
ZEEK_LOG_RETENTION_HOURS=banana
retention_once > "$env_dir/out" 2>&1; retention_once >> "$env_dir/out" 2>&1
[ -f "$LOG_DIR/x509.2026-01-01-01-00-00.log" ] || fail "a garbage retention value must keep everything"
[ "$(grep -c 'not a whole number' "$env_dir/out")" -eq 1 ] || fail "a garbage retention value must warn exactly once"

# 18. Durable markers: pruned only when the capture is gone AND the marker is
#     older than the retention window; a marker of a capture still in
#     pcap-input is kept; deleted job logs do not bring the capture back.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir -p "$STATE_DIR/gone" "$STATE_DIR/kept" "$STATE_DIR/fresh" "$PCAP_DIR/kept"
echo done > "$STATE_DIR/gone/a.pcap"; echo done > "$STATE_DIR/kept/a.pcap"; echo done > "$STATE_DIR/fresh/a.pcap"
echo ok > "$PCAP_DIR/kept/a.pcap"
touch -t "$old" "$STATE_DIR/gone/a.pcap" "$STATE_DIR/kept/a.pcap"
retention_once > "$env_dir/out" 2>&1
[ ! -e "$STATE_DIR/gone/a.pcap" ] && [ ! -d "$STATE_DIR/gone" ] || fail "state: an old marker of a removed capture (and its empty directory) must go"
[ -f "$STATE_DIR/kept/a.pcap" ] || fail "state: the marker of a capture still in pcap-input must stay"
[ -f "$STATE_DIR/fresh/a.pcap" ] || fail "state: a recent marker must stay even if its capture is missing"

# 19. The whole cycle: retention removes a finished job's logs and the
#     capture is NOT processed again.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir "$PCAP_DIR/cycle"; echo ok > "$PCAP_DIR/cycle/a.pcap"
scan_once > "$env_dir/out" 2>&1
touch -t "$old" "$LOG_DIR/cycle/.done"
retention_once > "$env_dir/out" 2>&1
[ ! -e "$LOG_DIR/cycle" ] || fail "cycle: the old job logs should have been removed"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 1 ] || fail "cycle: retention made the sensor process the capture again"

# 20. entrypoint.sh runs under `set -e`, and its background loops inherit it:
#     the loop bodies must survive every expected failure (a non-empty state
#     directory that rmdir refuses, an empty log directory, a waiting capture,
#     a failed capture, a removal that fails). Run the functions under `sh -e`
#     and require success.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir -p "$STATE_DIR/busy" "$PCAP_DIR/busy" "$PCAP_DIR/waiting" "$PCAP_DIR/bad"
echo done > "$STATE_DIR/busy/a.pcap"; echo ok > "$PCAP_DIR/busy/a.pcap"
echo ok > "$PCAP_DIR/waiting/w.pcap"; echo broken > "$PCAP_DIR/bad/b.pcap"
touch -t "$old" "$STATE_DIR/busy/a.pcap" "$PCAP_DIR/busy/a.pcap" "$PCAP_DIR/bad/b.pcap"
"$TEST_SH" -e -c '
    LOG_DIR=$1; PCAP_DIR=$2; STATE_DIR=$3; PCAP_SETTLE_SECONDS=10; ZEEK_LOG_RETENTION_HOURS=1
    export STUB_CALLS
    . "$4/sensor-lib.sh"
    scan_once; scan_once; retention_once; retention_once
' sh "$LOG_DIR" "$PCAP_DIR" "$STATE_DIR" "$here" > "$env_dir/out" 2>&1 \
    || fail "the loop bodies must survive set -e (see $env_dir/out): $(tail -3 "$env_dir/out" | tr '\n' ' ')"
[ -f "$STATE_DIR/busy/a.pcap" ] || fail "set -e run: a marker of a capture that still exists was removed"

# 20b. Removals that fail must not end the loop under set -e, and the loop
#      goes on to the next candidate. Permissions do not bind root.
if [ "$(id -u)" -ne 0 ]; then
    newenv
    ZEEK_LOG_RETENTION_HOURS=1
    # a_locked cannot be removed (a subdirectory nobody may enter); b_ok can.
    mkdir -p "$LOG_DIR/a_locked/sub" "$LOG_DIR/b_ok"
    echo x > "$LOG_DIR/a_locked/sub/file"
    touch "$LOG_DIR/a_locked/.done" "$LOG_DIR/b_ok/.done"
    touch -t "$old" "$LOG_DIR/a_locked/.done" "$LOG_DIR/b_ok/.done"
    chmod 000 "$LOG_DIR/a_locked/sub"
    "$TEST_SH" -e -c '
        LOG_DIR=$1; PCAP_DIR=$2; STATE_DIR=$3; ZEEK_LOG_RETENTION_HOURS=1
        . "$4/sensor-lib.sh"
        retention_once
    ' sh "$LOG_DIR" "$PCAP_DIR" "$STATE_DIR" "$here" > "$env_dir/out" 2>&1 \
        || fail "a failing rm -rf must not end retention under set -e (see $env_dir/out)"
    chmod 755 "$LOG_DIR/a_locked/sub"
    [ -d "$LOG_DIR/a_locked" ] || fail "set -e run: the undeletable job directory should still exist"
    [ ! -e "$LOG_DIR/b_ok" ] || fail "set -e run: the loop must go on to the next candidate after a failed removal"
    grep -q 'could not remove' "$env_dir/out" || fail "set -e run: a failed removal should be reported"

    # Read-only log and state directories: every rm and rmdir fails.
    newenv
    ZEEK_LOG_RETENTION_HOURS=1
    touch "$LOG_DIR/x509.2026-01-01-01-00-00.log"; touch -t "$old" "$LOG_DIR/x509.2026-01-01-01-00-00.log"
    mkdir -p "$LOG_DIR/ro_job" "$STATE_DIR/gone"
    touch "$LOG_DIR/ro_job/.done"; touch -t "$old" "$LOG_DIR/ro_job/.done"
    echo done > "$STATE_DIR/gone/a.pcap"; touch -t "$old" "$STATE_DIR/gone/a.pcap"
    # a capture elsewhere, so marker pruning is not skipped and its rm is reached
    mkdir -p "$PCAP_DIR/other"; echo ok > "$PCAP_DIR/other/x.pcap"
    chmod 555 "$LOG_DIR" "$STATE_DIR" "$STATE_DIR/gone"
    "$TEST_SH" -e -c '
        LOG_DIR=$1; PCAP_DIR=$2; STATE_DIR=$3; ZEEK_LOG_RETENTION_HOURS=1
        . "$4/sensor-lib.sh"
        retention_once; retention_once
    ' sh "$LOG_DIR" "$PCAP_DIR" "$STATE_DIR" "$here" > "$env_dir/out" 2>&1 \
        || fail "failing removals in read-only directories must not end retention under set -e (see $env_dir/out)"
    chmod 755 "$LOG_DIR" "$STATE_DIR" "$STATE_DIR/gone"
fi

# 21. An hours value that is huge (or wraps in shell arithmetic)
#     disables retention with one warning; leading zeros are accepted.
for v in 1234567 3381903080180084463 999999999999999999999; do
    newenv
    ZEEK_LOG_RETENTION_HOURS=$v
    touch "$LOG_DIR/x509.2020-01-01-01-00-00.log"; touch -t "$old" "$LOG_DIR/x509.2020-01-01-01-00-00.log"
    touch "$LOG_DIR/ssl.2026-09-28-17-00-00.log"
    mkdir "$LOG_DIR/fresh"; touch "$LOG_DIR/fresh/.done"
    retention_once > "$env_dir/out" 2>&1; retention_once >> "$env_dir/out" 2>&1
    [ -f "$LOG_DIR/x509.2020-01-01-01-00-00.log" ] && [ -f "$LOG_DIR/ssl.2026-09-28-17-00-00.log" ] && [ -d "$LOG_DIR/fresh" ] || fail "hours=$v: retention must be off"
    [ "$(grep -c 'not a whole number of hours between 0 and 999999' "$env_dir/out")" -eq 1 ] || fail "hours=$v: expected exactly one warning"
done
for v in 0168 08; do
    newenv
    ZEEK_LOG_RETENTION_HOURS=$v
    touch "$LOG_DIR/x509.2020-01-01-01-00-00.log"; touch -t "$old" "$LOG_DIR/x509.2020-01-01-01-00-00.log"
    touch "$LOG_DIR/ssl.2026-09-28-17-00-00.log"
    retention_once > "$env_dir/out" 2>&1
    [ ! -e "$LOG_DIR/x509.2020-01-01-01-00-00.log" ] || fail "hours=$v: an old rotated log must be deleted"
    [ -f "$LOG_DIR/ssl.2026-09-28-17-00-00.log" ] || fail "hours=$v: a fresh rotated log must stay"
    [ ! -s "$env_dir/out" ] || fail "hours=$v: no warning expected: $(cat "$env_dir/out")"
done

# 22. Only a dot directory directly under LOG_DIR is ever pruned as
#     the state directory; an empty or root LOG_DIR is a no-op.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir -p "$PCAP_DIR/x"; echo ok > "$PCAP_DIR/x/a.pcap"
STATE_DIR="$env_dir/shared"; mkdir -p "$STATE_DIR/app"
echo cfg > "$STATE_DIR/app/config"; touch -t "$old" "$STATE_DIR/app/config"
retention_once > "$env_dir/out" 2>&1
[ -f "$env_dir/shared/app/config" ] || fail "state: a STATE_DIR outside LOG_DIR must never be pruned"
STATE_DIR="$LOG_DIR/state"; mkdir -p "$STATE_DIR/app"
echo cfg > "$STATE_DIR/app/config"; touch -t "$old" "$STATE_DIR/app/config"
retention_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/state/app/config" ] || fail "state: a STATE_DIR that is not a dot directory must never be pruned"
STATE_DIR="$LOG_DIR/.."; mkdir -p "$env_dir/dd"
retention_once > "$env_dir/out" 2>&1
[ -f "$env_dir/shared/app/config" ] || fail "state: LOG_DIR/.. must never be pruned"
mkdir -p "$env_dir/stub" "$env_dir/cwd"
for c in find rm rmdir; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/stubcalls"\n' "$c" "$env_dir" > "$env_dir/stub/$c"
    chmod +x "$env_dir/stub/$c"
done
for bad in "" / //; do
    ( cd "$env_dir/cwd" && PATH="$env_dir/stub:$PATH" && LOG_DIR="$bad" && STATE_DIR="" && retention_once ) > "$env_dir/out" 2>&1
    [ ! -e "$env_dir/stubcalls" ] || fail "LOG_DIR='$bad' must make retention a no-op (ran: $(cat "$env_dir/stubcalls"))"
done

# 23. A bad interval falls back to 3600 with one warning.
newenv
for v in abc 0 10s -5 0000 1234567; do
    ZEEK_RETENTION_INTERVAL_SECONDS=$v
    got=$(retention_interval 2> "$env_dir/err")
    [ "$got" = 3600 ] || fail "interval '$v' must fall back to 3600, got '$got'"
    [ "$(grep -c 'ZEEK_RETENTION_INTERVAL_SECONDS' "$env_dir/err")" -eq 1 ] || fail "interval '$v' must warn once"
done
for pair in 30:30 0060:60 3600:3600; do
    ZEEK_RETENTION_INTERVAL_SECONDS=${pair%%:*}
    got=$(retention_interval 2> "$env_dir/err")
    [ "$got" = "${pair##*:}" ] && [ ! -s "$env_dir/err" ] || fail "interval ${pair%%:*} must be accepted silently as ${pair##*:}, got '$got'"
done

# 24. Retention only removes a finished job directory once its
#     capture is accounted for by the durable state (or is gone); legacy
#     directories of older sensors are adopted by the watcher first.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir "$PCAP_DIR/legacy"; echo ok > "$PCAP_DIR/legacy/a.pcap"
mkdir "$LOG_DIR/legacy"; touch "$LOG_DIR/legacy/x509.log" "$LOG_DIR/legacy/.done"; touch -t "$old" "$LOG_DIR/legacy/.done"
retention_once > "$env_dir/out" 2>&1
[ -d "$LOG_DIR/legacy" ] || fail "upgrade: a legacy directory whose capture has no marker must not be removed"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 0 ] || fail "upgrade: the legacy directory must be adopted without running Zeek"
retention_once > "$env_dir/out" 2>&1
[ ! -e "$LOG_DIR/legacy" ] || fail "upgrade: once adopted, the legacy directory must be removed"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 0 ] || fail "upgrade: retention made the sensor process the legacy capture"

newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir -p "$PCAP_DIR/n1" "$PCAP_DIR/n3" "$PCAP_DIR/n4" "$PCAP_DIR/n5" "$STATE_DIR/n1"
echo ok > "$PCAP_DIR/n1/a.pcap"; echo ok > "$PCAP_DIR/n3/a.pcap"; echo ok > "$PCAP_DIR/n4/a.pcap"; echo ok > "$PCAP_DIR/n5/a.pcap"
echo done > "$STATE_DIR/n1/a.pcap"
for d in n1 n2 n3 n4 n5; do
    mkdir "$LOG_DIR/$d"; touch "$LOG_DIR/$d/.done"; touch -t "$old" "$LOG_DIR/$d/.done"
done
echo "n1/a.pcap" > "$LOG_DIR/n1/.source"   # capture and marker exist: remove
echo "n2/a.pcap" > "$LOG_DIR/n2/.source"   # capture gone, no marker: remove
echo "n3/a.pcap" > "$LOG_DIR/n3/.source"   # capture exists, no marker: keep
: > "$LOG_DIR/n4/.source"                  # empty source: keep
retention_once > "$env_dir/out" 2>&1
[ ! -e "$LOG_DIR/n1" ] || fail "source: capture accounted for by its marker: the directory must go"
[ ! -e "$LOG_DIR/n2" ] || fail "source: a directory whose capture is gone must go even without a marker"
[ -d "$LOG_DIR/n3" ] || fail "source: a capture without a marker must keep its directory"
[ -d "$LOG_DIR/n4" ] || fail "source: an empty .source must keep the directory"
if [ "$(id -u)" -ne 0 ]; then
    echo "n5/a.pcap" > "$LOG_DIR/n5/.source"; chmod 000 "$LOG_DIR/n5/.source"
    "$TEST_SH" -e -c '
        LOG_DIR=$1; PCAP_DIR=$2; STATE_DIR=$3; ZEEK_LOG_RETENTION_HOURS=1
        . "$4/sensor-lib.sh"
        retention_once
    ' sh "$LOG_DIR" "$PCAP_DIR" "$STATE_DIR" "$here" > "$env_dir/out" 2>&1 \
        || fail "an unreadable .source must not end retention under set -e"
    chmod 644 "$LOG_DIR/n5/.source"
    [ -d "$LOG_DIR/n5" ] || fail "source: an unreadable .source must keep the directory"
fi

# 25. An empty or unmounted inbox must not wipe the markers.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir -p "$STATE_DIR/gone"; echo done > "$STATE_DIR/gone/a.pcap"; touch -t "$old" "$STATE_DIR/gone/a.pcap"
retention_once > "$env_dir/out" 2>&1
[ -f "$STATE_DIR/gone/a.pcap" ] || fail "state: with no captures in pcap-input no marker may be pruned"

# 26. A symlinked state directory is never pruned.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir -p "$PCAP_DIR/x" "$env_dir/outside/x"; echo ok > "$PCAP_DIR/x/a.pcap"
echo keep > "$env_dir/outside/x/y"; touch -t "$old" "$env_dir/outside/x/y"
ln -s "$env_dir/outside" "$LOG_DIR/.state"
retention_once > "$env_dir/out" 2>&1
[ -f "$env_dir/outside/x/y" ] || fail "a symlinked state directory must never be pruned"
grep -q 'is a symlink; not pruning processed markers' "$env_dir/out" || fail "a symlinked state directory should be reported"

# 27. Backslashes in job names survive in .source (dash and macOS
#     sh interpret escapes in echo), so no false collision and the retention
#     accounting still finds the capture.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir "$PCAP_DIR"/'b\tq'; echo ok > "$PCAP_DIR"/'b\tq'/a.pcap
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 1 ] || fail "backslash job: expected 1 run, got $(calls)"
[ "$(cat "$LOG_DIR"/'b\tq'/.source)" = 'b\tq/a.pcap' ] || fail "backslash job: .source must hold the literal name"
rm -f "$STATE_DIR"/'b\tq'/a.pcap
scan_once > "$env_dir/out" 2>&1
grep -q collides "$STATE_DIR"/'b\tq'/a.pcap 2>/dev/null && fail "backslash job: falsely refused as a collision"
[ "$(calls)" -eq 1 ] || fail "backslash job: the capture must not run again, got $(calls)"
rm -f "$STATE_DIR"/'b\tq'/a.pcap
touch -t "$old" "$LOG_DIR"/'b\tq'/.done
retention_once > "$env_dir/out" 2>&1
[ -d "$LOG_DIR"/'b\tq' ] || fail "backslash job: an unmarked capture must keep its log directory"

# 28. An empty .source (a failed write) is treated as absent.
newenv
mkdir "$PCAP_DIR/e1" "$LOG_DIR/e1"; echo ok > "$PCAP_DIR/e1/a.pcap"; : > "$LOG_DIR/e1/.source"
scan_once > "$env_dir/out" 2>&1
[ "$(calls)" -eq 1 ] && [ -f "$LOG_DIR/e1/.done" ] || fail "empty .source: the capture must be processed normally"
grep -q collides "$STATE_DIR/e1/a.pcap" 2>/dev/null && fail "empty .source: falsely refused as a collision"
[ "$(cat "$LOG_DIR/e1/.source")" = "e1/a.pcap" ] || fail "empty .source: must be rewritten"

# 29. A log directory whose .source names a capture that no longer exists is
#     stale, not a collision: the new capture gets no permanent marker, the
#     situation is logged once, and it runs once the stale directory is gone
#     (removed by hand or by retention).
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir "$PCAP_DIR/site"; echo ok > "$PCAP_DIR/site/old.pcap"
scan_once > "$env_dir/out" 2>&1
rm -f "$PCAP_DIR/site/old.pcap"; echo ok > "$PCAP_DIR/site/new.pcap"
scan_once > "$env_dir/out" 2>&1; scan_once >> "$env_dir/out" 2>&1
[ ! -e "$STATE_DIR/site/new.pcap" ] || fail "stale source: the new capture must get no marker (got: $(cat "$STATE_DIR/site/new.pcap" 2>/dev/null))"
[ "$(calls)" -eq 1 ] || fail "stale source: the new capture must wait for the stale directory to go, got $(calls) runs"
[ "$(grep -c 'no longer exists' "$env_dir/out")" -eq 1 ] || fail "stale source: expected exactly one log line"
rm -rf "$LOG_DIR/site"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/site/.done" ] && [ "$(calls)" -eq 2 ] || fail "stale source: after removing the directory the capture must be processed"
# The same through retention: the old capture's marker accounts for it, so
# the aged directory is removed and the new capture then runs.
newenv
ZEEK_LOG_RETENTION_HOURS=1
mkdir "$PCAP_DIR/site"; echo ok > "$PCAP_DIR/site/old.pcap"
scan_once > "$env_dir/out" 2>&1
rm -f "$PCAP_DIR/site/old.pcap"; echo ok > "$PCAP_DIR/site/new.pcap"
scan_once > "$env_dir/out" 2>&1
touch -t "$old" "$LOG_DIR/site/.done"
retention_once > "$env_dir/out" 2>&1
[ ! -e "$LOG_DIR/site" ] || fail "stale source: retention must remove the aged stale directory"
scan_once > "$env_dir/out" 2>&1
[ -f "$LOG_DIR/site/.done" ] && [ "$(calls)" -eq 2 ] || fail "stale source: after retention the new capture must be processed"
# (A collision with a capture that is still present stays permanent: test 8.)

# 30. A settle value with more than 9 digits is invalid: one warning, the
#     default of 10 is used.
newenv
mkdir "$PCAP_DIR/job30" "$PCAP_DIR/job30b"
echo ok > "$PCAP_DIR/job30/fresh.pcap"; echo ok > "$PCAP_DIR/job30b/old.pcap"
touch -t "$old" "$PCAP_DIR/job30b/old.pcap"
PCAP_SETTLE_SECONDS=99999999999999999999
scan_once > "$env_dir/out" 2>&1; scan_once >> "$env_dir/out" 2>&1
[ ! -e "$LOG_DIR/job30" ] || fail "long settle value: a fresh capture must still wait"
[ -f "$LOG_DIR/job30b/.done" ] || fail "long settle value: an old capture must settle with the default"
[ "$(grep -c 'PCAP_SETTLE_SECONDS' "$env_dir/out")" -eq 1 ] || fail "long settle value: expected exactly one warning"

if [ "$fails" -eq 0 ]; then
    echo "PASS: sensor-lib.sh"
else
    echo "$fails check(s) failed" >&2
    exit 1
fi
