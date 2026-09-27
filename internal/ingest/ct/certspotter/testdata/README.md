# CertSpotter test fixtures

## `real_certspotter_letsencrypt_org_response.json`

A captured response from SSLMate CertSpotter's `/v1/issuances` endpoint
for `letsencrypt.org`. Load-bearing regression gate for the package's
`Issuance` JSON schema — if SSLMate changes the shape, this fixture
test breaks before any production drift.

### Why `letsencrypt.org`?

- Public, high-traffic CT-monitored domain → guaranteed non-empty
- Public org → no operator-infrastructure leakage into a committed file
- Self-issues frequently → reproducible if regenerated

### Entry count

The fixture is non-empty — the regression test only requires `len > 0`;
size varies with CT activity (letsencrypt.org currently returns 2 entries
for its root domain without subdomains).

### Regen recipe

```bash
curl -fsS 'https://api.certspotter.com/v1/issuances?domain=letsencrypt.org&include_subdomains=false&expand=dns_names&expand=issuer&expand=cert' \
  > internal/ingest/ct/certspotter/testdata/real_certspotter_letsencrypt_org_response.json
```

If the response is >5 MB, truncate after page 1 (whole entries only —
keep JSON array syntactically valid).

The fixture is consumed by `TestParseIssuances_AgainstRealCertSpotterResponse`
in `../client_test.go`. After regen, re-run:

```bash
go test ./internal/ingest/ct/certspotter/ -run TestParseIssuances_AgainstRealCertSpotterResponse -count=1 -v
```

A schema break shows up as a decode failure or a zero-field assertion.
