#!/bin/sh
# Builds the Zeek sensor image and runs it, with its real entrypoint, over
# two offline PCAP jobs:
#   ok  - testdata/tls.pcap (TLS 1.2 and 1.3 to a throwaway server): must
#         produce x509 logs carrying the certificates and ssl logs with
#         their chains, and be marked .done;
#   bad - a file that is not a PCAP: must be marked .failed, never .done,
#         so CipherFlag does not read a job Zeek could not process.
# Usage: docker/zeek/test-sensor.sh   (needs Docker; exits non-zero on failure)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
image=cipherflag-ce-zeek:sensor-test
work=$(mktemp -d)
name=cf-zeek-sensor-test-$$

cleanup() {
    docker container rm -f "$name" >/dev/null 2>&1 || true
    # On Linux the container writes the logs as root, so they may not be
    # removable here; that must not fail a passing run.
    rm -r "$work" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; docker logs "$name" >&2 2>&1 || true; exit 1; }

docker build -q -t "$image" "$here" >/dev/null

mkdir -p "$work/pcap-input/ok" "$work/pcap-input/bad" "$work/logs"
cp "$here/testdata/tls.pcap" "$work/pcap-input/ok/tls.pcap"
printf 'this is not a pcap\n' > "$work/pcap-input/bad/broken.pcap"

docker run -d --name "$name" \
    -v "$work/pcap-input:/pcap-input" -v "$work/logs:/zeek-logs" "$image" >/dev/null

for _ in $(seq 1 60); do
    ok_state=none; bad_state=none
    [ -f "$work/logs/ok/.done" ] && ok_state=done
    [ -f "$work/logs/ok/.failed" ] && ok_state=failed
    [ -f "$work/logs/bad/.done" ] && bad_state=done
    [ -f "$work/logs/bad/.failed" ] && bad_state=failed
    [ "$ok_state" != none ] && [ "$bad_state" != none ] && break
    sleep 1
done

[ "$ok_state" = done ] || fail "the TLS job ended as '$ok_state', want done"
[ "$bad_state" = failed ] || fail "the broken job ended as '$bad_state', want failed"

x509=$(ls "$work/logs/ok"/x509*.log 2>/dev/null | head -1)
ssl=$(ls "$work/logs/ok"/ssl*.log 2>/dev/null | head -1)
[ -n "$x509" ] || fail "no x509 log for the TLS job"
[ -n "$ssl" ] || fail "no ssl log for the TLS job"
[ "$(grep -c '"cert":"' "$x509")" -eq 2 ] || fail "x509 log does not carry both certificates (log-certs-base64)"
[ "$(grep -c '"cert_chain_fps":\["' "$ssl")" -eq 2 ] || fail "ssl log does not have the two TLS 1.2 chains"

echo "PASS: Zeek sensor image processes PCAP jobs and marks failed ones"
