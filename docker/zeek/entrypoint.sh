#!/bin/sh
set -e
LOG_DIR="${ZEEK_LOG_DIR:-/zeek-logs}"
PCAP_DIR="${PCAP_INPUT_DIR:-/pcap-input}"
INTERFACE="${NETWORK_INTERFACE:-}"
# Not taken from the environment: retention prunes this directory.
STATE_DIR="$LOG_DIR/.state"
mkdir -p "$LOG_DIR" "$PCAP_DIR"

# shellcheck disable=SC1091
. "$(dirname "$0")/sensor-lib.sh"

pcap_watcher &
retention_loop &

if [ -n "$INTERFACE" ]; then
    echo "Starting live capture on interface: $INTERFACE"
    cd "$LOG_DIR"
    exec zeek -i "$INTERFACE" /usr/local/zeek/share/zeek/site/local.zeek
else
    echo "No NETWORK_INTERFACE set, running in PCAP-only mode"
    wait
fi
