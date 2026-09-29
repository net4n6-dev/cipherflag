@load policy/tuning/json-logs
# Logs each certificate's DER (base64) in x509.log's "cert" field, so
# CipherFlag stores the whole certificate. Replaces extract-certs-pem, which
# Zeek 9 removed.
@load policy/protocols/ssl/log-certs-base64
# NIC checksum offloading leaves captured packets with invalid TCP
# checksums; Zeek drops those by default and then logs no TLS at all.
redef ignore_checksums = T;
redef Log::default_rotation_interval = 1 hr;
