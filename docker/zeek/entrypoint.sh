#!/bin/sh
set -e
LOG_DIR="${ZEEK_LOG_DIR:-/zeek-logs}"
PCAP_DIR="${PCAP_INPUT_DIR:-/pcap-input}"
INTERFACE="${NETWORK_INTERFACE:-}"
mkdir -p "$LOG_DIR" "$PCAP_DIR"

pcap_watcher() {
    echo "PCAP watcher: monitoring $PCAP_DIR"
    while true; do
        for pcap in "$PCAP_DIR"/*/*.pcap "$PCAP_DIR"/*/*.pcapng; do
            [ -f "$pcap" ] || continue
            job_dir=$(dirname "$pcap")
            job_id=$(basename "$job_dir")
            out_dir="$LOG_DIR/$job_id"
            done_marker="$out_dir/.done"
            [ -f "$done_marker" ] && continue
            echo "Processing PCAP: $pcap (job: $job_id)"
            mkdir -p "$out_dir"
            cd "$out_dir"
            zeek -r "$pcap" /usr/local/zeek/share/zeek/site/local.zeek 2>&1 || true
            touch "$done_marker"
            echo "Completed PCAP: $pcap"
            cd /
        done
        sleep 5
    done
}

pcap_watcher &

if [ -n "$INTERFACE" ]; then
    echo "Starting live capture on interface: $INTERFACE"
    cd "$LOG_DIR"
    exec zeek -i "$INTERFACE" /usr/local/zeek/share/zeek/site/local.zeek
else
    echo "No NETWORK_INTERFACE set, running in PCAP-only mode"
    wait
fi
