Real Zeek 9.0.0 JSON logs, generated for tests; not hand-written.

A throwaway Alpine container captured three TLS connections to
`openssl s_server` on loopback (two TLS 1.2 handshakes with different SNI,
one TLS 1.3), with a throwaway root CA and server certificate. Zeek 9.0.0
(the cipherflag-ce-zeek image) read the PCAP with this policy:

    @load policy/tuning/json-logs
    @load policy/protocols/ssl/log-certs-base64
    redef ignore_checksums = T;

- `x509.log`: the server and CA certificates, with the DER in `cert`.
- `ssl.log`: the three connections; the TLS 1.3 one has no `cert_chain_fps`.

Only public certificates are in these files. The keys never left the
container.
