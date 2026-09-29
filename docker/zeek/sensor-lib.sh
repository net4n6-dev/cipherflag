#!/bin/sh
# Functions of the Zeek sensor. Sourced by entrypoint.sh, and by
# test-entrypoint.sh with a stub `zeek`. POSIX sh; no `local`.
#
# The caller sets LOG_DIR and PCAP_DIR. Optional:
#   STATE_DIR            durable state, default $LOG_DIR/.state
#   PCAP_SETTLE_SECONDS  a capture must not have changed for this long before
#                        it is processed (default 10), so a copy in progress
#                        is not run through Zeek truncated
#   ZEEK_SITE_SCRIPT     the site script passed to zeek
#   ZEEK_LOG_RETENTION_HOURS          hours to keep rotated logs and finished
#                        job logs (default 168, 0 keeps everything)
#   ZEEK_RETENTION_INTERVAL_SECONDS   pause between retention passes (3600)
#
# The watcher runs under `set -e` in the entrypoint: nothing in here may let
# an expected failure (an unwritable directory, a name too long) end it.

STATE_DIR="${STATE_DIR:-$LOG_DIR/.state}"
PCAP_SETTLE_SECONDS="${PCAP_SETTLE_SECONDS:-10}"
ZEEK_SITE_SCRIPT="${ZEEK_SITE_SCRIPT:-/usr/local/zeek/share/zeek/site/local.zeek}"
WAITING_FOR="${WAITING_FOR:-}"
FAILED_LOGGED="${FAILED_LOGGED:-}"
SETTLE_WARNED="${SETTLE_WARNED:-}"
ZEEK_LOG_RETENTION_HOURS="${ZEEK_LOG_RETENTION_HOURS:-168}"
ZEEK_RETENTION_INTERVAL_SECONDS="${ZEEK_RETENTION_INTERVAL_SECONDS:-3600}"
RETENTION_WARNED="${RETENTION_WARNED:-}"
STATE_LINK_WARNED="${STATE_LINK_WARNED:-}"

# Longest log directory name the sensor will try to create. Filesystems stop
# at 255 bytes; this leaves room and is far beyond any real job name.
MAX_OUT_NAME=200

# file_mtime FILE prints the modification time in epoch seconds, following
# symlinks. GNU stat in the sensor image, BSD stat on a developer's Mac.
file_mtime() {
    stat -L -c %Y "$1" 2>/dev/null || stat -L -f %m "$1"
}

# capture_settled FILE succeeds when the file has not changed for
# PCAP_SETTLE_SECONDS. A file being copied keeps its mtime moving; one moved
# into place with mv keeps the old mtime and is processed at once. A value
# that is not a whole number of at most 9 digits falls back to 10 (warned
# once).
capture_settled() {
    cs_settle="$PCAP_SETTLE_SECONDS"
    case "$cs_settle" in
        ''|*[!0-9]*) cs_settle="" ;;
    esac
    if [ "${#cs_settle}" -eq 0 ] || [ "${#cs_settle}" -gt 9 ]; then
        if [ -z "$SETTLE_WARNED" ]; then
            echo "warning: PCAP_SETTLE_SECONDS=$PCAP_SETTLE_SECONDS is not a whole number of seconds (at most 9 digits); using 10"
            SETTLE_WARNED=1
        fi
        cs_settle=10
    fi
    cs_now=$(date +%s)
    cs_mtime=$(file_mtime "$1") || return 1
    [ $((cs_now - cs_mtime)) -ge "$cs_settle" ]
}

# captures_in JOB_DIR prints how many captures the directory holds.
captures_in() {
    ci_count=0
    for ci_file in "$1"/*.pcap "$1"/*.pcapng; do
        [ -f "$ci_file" ] && ci_count=$((ci_count + 1))
    done
    echo "$ci_count"
}

# note_failure PCAP REASON logs a failed capture once per capture per process
# lifetime, so a capture that keeps failing does not flood the log.
note_failure() {
    case "$FAILED_LOGGED" in
        *"|$1|"*) ;;
        *)
            echo "FAILED PCAP: $1 ($2)"
            FAILED_LOGGED="$FAILED_LOGGED|$1|"
            ;;
    esac
    return 0
}

# process_capture PCAP runs Zeek over one capture unless it was processed
# before or is still being written. Always returns 0.
process_capture() {
    pc_pcap="$1"
    pc_job_dir=${pc_pcap%/*}
    pc_job=${pc_job_dir##*/}
    pc_file=${pc_pcap##*/}
    pc_state="$STATE_DIR/$pc_job/$pc_file"

    # The common case on every idle scan, so nothing else runs before it.
    [ -f "$pc_state" ] && return 0

    if [ "$(captures_in "$pc_job_dir")" -gt 1 ]; then
        pc_out_name="${pc_job}--${pc_file}"
    else
        pc_out_name="$pc_job"
    fi
    pc_out="$LOG_DIR/$pc_out_name"

    # A name no filesystem accepts can never succeed: mark it failed for good.
    if [ "${#pc_out_name}" -gt "$MAX_OUT_NAME" ]; then
        { mkdir -p "$STATE_DIR/$pc_job" && echo "failed: log directory name too long" > "$pc_state"; } 2>/dev/null || true
        note_failure "$pc_pcap" "name too long for a log directory"
        return 0
    fi

    # Two captures must never write into one log directory. This comes before
    # the legacy-marker check: a .done left by the other capture is not proof
    # that this one was processed.
    if [ -s "$pc_out/.source" ]; then
        pc_src=$(cat "$pc_out/.source" 2>/dev/null) || pc_src=""
    else
        pc_src=""
    fi
    if [ -n "$pc_src" ] && [ "$pc_src" != "$pc_job/$pc_file" ]; then
        if [ ! -e "$PCAP_DIR/$pc_src" ]; then
            # The capture that wrote these logs is gone: the directory is
            # stale, not shared. No marker, so the capture runs once retention
            # or an operator removes the directory.
            note_failure "$pc_pcap" "log directory $pc_out_name holds the logs of a capture that no longer exists; remove the directory or wait for retention"
            return 0
        fi
        { mkdir -p "$STATE_DIR/$pc_job" && echo "failed: log directory collides with another capture" > "$pc_state"; } 2>/dev/null || true
        note_failure "$pc_pcap" "its log directory $pc_out_name is used by another capture"
        return 0
    fi

    # Already processed by an older sensor, which wrote its marker into the
    # log directory (and no .source). Legacy markers only cover the
    # one-capture layout: a multi-capture job re-runs once after upgrading
    # (the store deduplicates the re-ingested sessions).
    if [ -f "$pc_out/.done" ] || [ -f "$pc_out/.failed" ]; then
        { mkdir -p "$STATE_DIR/$pc_job" && echo "processed by an earlier sensor" > "$pc_state"; } 2>/dev/null || true
        return 0
    fi

    # Vanished between the scan and now.
    [ -f "$pc_pcap" ] || return 0

    if ! capture_settled "$pc_pcap"; then
        case "$WAITING_FOR" in
            *"|$pc_pcap|"*) ;;
            *)
                echo "Waiting for $pc_pcap to stop changing before processing it"
                WAITING_FOR="$WAITING_FOR|$pc_pcap|"
                ;;
        esac
        return 0
    fi

    # A failure to create the directories is usually transient (a full or
    # unwritable volume): report it once, leave no marker, and retry next scan.
    if ! pc_err=$(mkdir -p "$STATE_DIR/$pc_job" 2>&1); then
        note_failure "$pc_pcap" "cannot create $STATE_DIR/$pc_job: $pc_err"
        return 0
    fi
    if ! pc_err=$(mkdir -p "$pc_out" 2>&1); then
        note_failure "$pc_pcap" "cannot create $pc_out: $pc_err"
        return 0
    fi
    if ! printf '%s\n' "$pc_job/$pc_file" 2>/dev/null > "$pc_out/.source"; then
        note_failure "$pc_pcap" "cannot write $pc_out/.source"
        return 0
    fi

    echo "Processing PCAP: $pc_pcap (job: $pc_job, logs: $pc_out_name)"
    # .done tells CipherFlag the logs are complete; a capture Zeek could not
    # process is marked .failed instead and not read.
    if (cd "$pc_out" && zeek -r "$pc_pcap" "$ZEEK_SITE_SCRIPT" 2>&1); then
        touch "$pc_out/.done" || echo "warning: could not create $pc_out/.done"
        echo "done" 2>/dev/null > "$pc_state" || echo "warning: could not write $pc_state"
        echo "Completed PCAP: $pc_pcap"
    else
        pc_status=$?
        echo "exit status $pc_status" 2>/dev/null > "$pc_out/.failed" || echo "warning: could not write $pc_out/.failed"
        echo "failed (exit status $pc_status)" 2>/dev/null > "$pc_state" || echo "warning: could not write $pc_state"
        echo "FAILED PCAP: $pc_pcap (Zeek could not process it; see the output above)"
    fi
    return 0
}

# scan_once processes every capture that is due.
scan_once() {
    for so_pcap in "$PCAP_DIR"/*/*.pcap "$PCAP_DIR"/*/*.pcapng; do
        [ -f "$so_pcap" ] || continue
        process_capture "$so_pcap"
    done
}

pcap_watcher() {
    echo "PCAP watcher: monitoring $PCAP_DIR"
    while true; do
        scan_once
        sleep 5
    done
}

# retention_hours prints ZEEK_LOG_RETENTION_HOURS as a plain number (leading
# zeros stripped), or fails when it is not a whole number of hours between 0
# and 999999. The cap keeps `hours * 60` far from shell arithmetic overflow.
retention_hours() {
    case "$ZEEK_LOG_RETENTION_HOURS" in
        ''|*[!0-9]*) return 1 ;;
    esac
    rh_n=$(printf '%s' "$ZEEK_LOG_RETENTION_HOURS" | sed 's/^0*//')
    [ "${#rh_n}" -le 6 ] || return 1
    echo "${rh_n:-0}"
}

# retention_interval prints the pause between retention passes: the configured
# whole number of seconds (1 to 999999), else 3600 with a warning on stderr.
retention_interval() {
    case "$ZEEK_RETENTION_INTERVAL_SECONDS" in
        ''|*[!0-9]*) ri_n="" ;;
        *) ri_n=$(printf '%s' "$ZEEK_RETENTION_INTERVAL_SECONDS" | sed 's/^0*//') ;;
    esac
    if [ -z "$ri_n" ] || [ "${#ri_n}" -gt 6 ]; then
        echo "warning: ZEEK_RETENTION_INTERVAL_SECONDS=$ZEEK_RETENTION_INTERVAL_SECONDS is not a whole number of seconds between 1 and 999999; using 3600" >&2
        echo 3600
        return 0
    fi
    echo "$ri_n"
}

# any_capture succeeds when pcap-input holds at least one capture file.
any_capture() {
    for ac_file in "$PCAP_DIR"/*/*.pcap "$PCAP_DIR"/*/*.pcapng; do
        [ -f "$ac_file" ] && return 0
    done
    return 1
}

# job_accounted_for JOB_LOG_DIR succeeds when the capture(s) the finished job
# directory holds the logs of are already recorded in the durable state or no
# longer exist, so deleting the directory cannot make the watcher run Zeek on
# them again. A directory an older sensor wrote (no .source) is not accounted
# for until the watcher has adopted it, which writes its state marker.
job_accounted_for() {
    ja_dir="$1"
    if [ -f "$ja_dir/.source" ]; then
        ja_src=$(cat "$ja_dir/.source" 2>/dev/null) || ja_src=""
        [ -n "$ja_src" ] || return 1
        [ -f "$STATE_DIR/$ja_src" ] && return 0
        [ -e "$PCAP_DIR/$ja_src" ] || return 0
        return 1
    fi
    ja_job=${ja_dir##*/}
    for ja_cap in "$PCAP_DIR/$ja_job"/*.pcap "$PCAP_DIR/$ja_job"/*.pcapng; do
        [ -f "$ja_cap" ] || continue
        [ -f "$STATE_DIR/$ja_job/${ja_cap##*/}" ] || return 1
    done
    return 0
}

# retention_once prunes what the sensor wrote and CipherFlag has long since
# read: rotated logs of every type and finished job directories older than
# ZEEK_LOG_RETENTION_HOURS, plus the processed markers of captures that are
# gone. It never touches live logs, a job directory without a marker or whose
# capture the durable state does not yet account for, or the state directory.
# 0 disables it. Always returns 0: every command that can fail is guarded,
# because the loop runs under `set -e` in the entrypoint.
retention_once() {
    case "$LOG_DIR" in
        ''|/|//) return 0 ;;
    esac
    if ! ro_hours=$(retention_hours); then
        if [ -z "$RETENTION_WARNED" ]; then
            echo "Retention: ZEEK_LOG_RETENTION_HOURS=$ZEEK_LOG_RETENTION_HOURS is not a whole number of hours between 0 and 999999; retention is off"
            RETENTION_WARNED=1
        fi
        return 0
    fi
    [ "$ro_hours" -gt 0 ] || return 0
    ro_mins=$((ro_hours * 60))

    # Rotated logs: <type>.<YYYY-MM-DD-HH-MM-SS>.log, optionally gzipped.
    find -H "$LOG_DIR" -maxdepth 1 -type f \
        \( -name '*.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9].log' \
        -o -name '*.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9].log.gz' \) \
        -mmin +"$ro_mins" -exec rm -f {} + || true

    # Finished job directories (the glob skips dot directories, so .state is
    # never a candidate). One whose capture the state does not account for is
    # skipped this pass; the watcher adopts it and a later pass removes it.
    for ro_marker in "$LOG_DIR"/*/.done "$LOG_DIR"/*/.failed; do
        [ -f "$ro_marker" ] || continue
        [ -n "$(find -H "$ro_marker" -mmin +"$ro_mins" 2>/dev/null)" ] || continue
        ro_dir=${ro_marker%/*}
        case "$ro_dir" in
            "$LOG_DIR"/?*) ;;
            *) continue ;;
        esac
        job_accounted_for "$ro_dir" || continue
        echo "Retention: removing finished job logs $ro_dir"
        rm -rf "$ro_dir" || echo "warning: could not remove $ro_dir"
    done

    # Processed markers whose capture is gone and that are old enough. Only
    # the sensor's own state directory (a dot directory directly under
    # LOG_DIR) is ever pruned, and not while pcap-input holds no capture at
    # all: an empty or unmounted inbox must not wipe the markers.
    case "$STATE_DIR" in
        "$LOG_DIR"/.?*)
            case "${STATE_DIR#"$LOG_DIR"/}" in
                */*|..) return 0 ;;
            esac
            ;;
        *) return 0 ;;
    esac
    if [ -L "$STATE_DIR" ]; then
        if [ -z "$STATE_LINK_WARNED" ]; then
            echo "Retention: $STATE_DIR is a symlink; not pruning processed markers"
            STATE_LINK_WARNED=1
        fi
        return 0
    fi
    any_capture || return 0
    for ro_state in "$STATE_DIR"/*/*; do
        [ -f "$ro_state" ] || continue
        ro_sdir=${ro_state%/*}
        ro_job=${ro_sdir##*/}
        [ -f "$PCAP_DIR/$ro_job/${ro_state##*/}" ] && continue
        [ -n "$(find -H "$ro_state" -mmin +"$ro_mins" 2>/dev/null)" ] || continue
        rm -f "$ro_state" || echo "warning: could not remove $ro_state"
    done
    for ro_sd in "$STATE_DIR"/*/; do
        [ -d "$ro_sd" ] || continue
        rmdir "$ro_sd" 2>/dev/null || true
    done
    return 0
}

retention_loop() {
    if rl_hours=$(retention_hours) && [ "$rl_hours" -gt 0 ]; then
        echo "Retention: pruning rotated logs and finished job logs older than $rl_hours hours (0 = keep everything)"
    else
        echo "Retention: off (rotated logs and finished job logs are kept)"
    fi
    rl_interval=$(retention_interval)
    while true; do
        retention_once
        sleep "$rl_interval"
    done
}
