# Integration Tests

CipherFlag has integration tests (build tag `integration`) that need
PostgreSQL. CI runs them on every push and pull request (the `integration`
job in `.github/workflows/ci.yml`). Unit tests need no database.

## Start a test database

```bash
docker run -d --name cipherflag-test-db \
  -e POSTGRES_DB=cipherflag \
  -e POSTGRES_USER=cipherflag \
  -e POSTGRES_PASSWORD=changeme \
  -p 5434:5432 \
  postgres:16

docker exec cipherflag-test-db psql -U cipherflag -c "CREATE DATABASE cipherflag_test;"
```

## Run the tests

```bash
# Unit tests
go test ./... -count=1

# Integration tests, the same command CI runs
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./... -count=1
```

`CIPHERFLAG_TEST_DB` is the connection string of the test database
(`internal/testdb/dsn.go`). Each package that uses `internal/testdb` gets
its own schema inside that database, dropped and recreated at the start of
the run, so packages can run in parallel and no `-p 1` flag is needed. The
database user must be allowed to create schemas.

## Stop and restart the database

```bash
docker stop cipherflag-test-db
docker start cipherflag-test-db  # restart later without recreating
```
