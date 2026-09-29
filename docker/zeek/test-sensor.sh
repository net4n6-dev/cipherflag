#!/bin/sh
# Builds the Zeek sensor image and runs it, with its real entrypoint, over
# three offline PCAP jobs:
#   ok    - testdata/tls.pcap (TLS 1.2 and 1.3 to a throwaway server): must
#           produce x509 logs carrying the certificates and ssl logs with
#           their chains, and be marked .done. Its durable marker
#           (/zeek-logs/.state/ok/tls.pcap) must exist, and deleting the
#           job's log directory must not make the capture run again;
#   bad   - a file that is not a PCAP: must be marked .failed, never .done,
#           so CipherFlag does not read a job Zeek could not process;
#   multi - two captures in one job: each is processed independently into
#           its own log directory (multi--one.pcap, multi--two.pcap).
# It also checks that the image starts with log retention running.
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

mkdir -p "$work/pcap-input/ok" "$work/pcap-input/bad" "$work/pcap-input/multi" "$work/logs"
cp "$here/testdata/tls.pcap" "$work/pcap-input/ok/tls.pcap"
printf 'this is not a pcap\n' > "$work/pcap-input/bad/broken.pcap"
cp "$here/testdata/tls.pcap" "$work/pcap-input/multi/one.pcap"
cp "$here/testdata/tls.pcap" "$work/pcap-input/multi/two.pcap"

docker run -d --name "$name" \
    -v "$work/pcap-input:/pcap-input" -v "$work/logs:/zeek-logs" "$image" >/dev/null

for _ in $(seq 1 60); do
    ok_state=none; bad_state=none; one_state=none; two_state=none
    [ -f "$work/logs/ok/.done" ] && ok_state=done
    [ -f "$work/logs/ok/.failed" ] && ok_state=failed
    [ -f "$work/logs/bad/.done" ] && bad_state=done
    [ -f "$work/logs/bad/.failed" ] && bad_state=failed
    [ -f "$work/logs/multi--one.pcap/.done" ] && one_state=done
    [ -f "$work/logs/multi--one.pcap/.failed" ] && one_state=failed
    [ -f "$work/logs/multi--two.pcap/.done" ] && two_state=done
    [ -f "$work/logs/multi--two.pcap/.failed" ] && two_state=failed
    [ "$ok_state" != none ] && [ "$bad_state" != none ] \
        && [ "$one_state" != none ] && [ "$two_state" != none ] && break
    sleep 1
done

[ "$ok_state" = done ] || fail "the TLS job ended as '$ok_state', want done"
[ "$bad_state" = failed ] || fail "the broken job ended as '$bad_state', want failed"

[ "$one_state" = done ] || fail "multi--one.pcap ended as '$one_state', want done"
[ "$two_state" = done ] || fail "multi--two.pcap ended as '$two_state', want done"

x509=$(ls "$work/logs/ok"/x509*.log 2>/dev/null | head -1)
ssl=$(ls "$work/logs/ok"/ssl*.log 2>/dev/null | head -1)
[ -n "$x509" ] || fail "no x509 log for the TLS job"
[ -n "$ssl" ] || fail "no ssl log for the TLS job"
[ "$(grep -c '"cert":"' "$x509")" -eq 2 ] || fail "x509 log does not carry both certificates (log-certs-base64)"
[ "$(grep -c '"cert_chain_fps":\["' "$ssl")" -eq 2 ] || fail "ssl log does not have the two TLS 1.2 chains"

for cap in multi--one.pcap multi--two.pcap; do
    mx=$(ls "$work/logs/$cap"/x509*.log 2>/dev/null | head -1)
    [ -n "$mx" ] || fail "no x509 log for $cap"
    [ "$(grep -c '"cert":"' "$mx")" -eq 2 ] || fail "x509 log of $cap does not carry both certificates"
done

[ -f "$work/logs/.state/ok/tls.pcap" ] || fail "no durable processed marker for the TLS job"

# Deleting a finished job's logs must not make the capture run again. The
# container writes as root, so remove them from inside it.
docker exec "$name" rm -rf /zeek-logs/ok
sleep 12
[ ! -e "$work/logs/ok" ] || fail "the TLS job was processed again after its logs were deleted"
[ -f "$work/logs/.state/ok/tls.pcap" ] || fail "the processed marker vanished after the job's logs were deleted"

docker logs "$name" 2>&1 | grep -q 'Retention: pruning' || fail "log retention is not running in the sensor"

echo "PASS: Zeek sensor image processes PCAP jobs and marks failed ones"
