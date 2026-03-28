# Setup Wizard

Interactive CLI wizard (`cipherflag setup`) that walks a user through configuring and deploying CipherFlag with network capture and Venafi integration. Targets security analysts who know Docker but not Go, Zeek, or TOML.

## Flow

Four steps after pre-flight checks:

1. **Installation directory** — where to write config files (default `./cipherflag`)
2. **Network capture** — list interfaces, user picks one for Zeek
3. **Venafi integration** — Cloud (API key), TPP (OAuth2), or skip
4. **Deploy** — pull images, optionally start services

## Pre-flight Checks

Before starting the wizard, verify:

- `docker` binary exists and responds to `docker version`
- `docker compose` (v2) or `docker-compose` (v1) is available
- Print versions if found, exit with clear install instructions if missing

## Step 1: Installation Directory

Prompt for directory path. Default: `./cipherflag`.

- Create the directory if it doesn't exist
- Create `config/` subdirectory inside it
- If directory already exists and contains `docker-compose.yml`, warn and ask to overwrite

## Step 2: Network Capture

List available network interfaces using Go's `net.Interfaces()`:

- Show name, first IPv4 address, and status (up/down)
- Mark loopback interfaces so user can avoid them
- User selects by number
- Store the interface name for the `.env` file

## Step 3: Venafi Integration

Prompt for platform choice:

**Option 1: Venafi Cloud**
- Prompt for API key (masked input via `term.ReadPassword`)
- Prompt for region: `us` or `eu` (default `us`)
- Validate credentials by calling `CloudClient.ValidateConnection(ctx)`
- On success, show cert count message
- On failure, show error and offer to retry or skip

**Option 2: Venafi TPP**
- Prompt for base URL
- Prompt for client ID
- Prompt for refresh token (masked input)
- Prompt for policy folder (default `\VED\Policy\Discovered\CipherFlag`)
- Validate credentials by calling `TPPAdapter.ValidateConnection(ctx)`
- On success, confirm connection
- On failure, show error and offer to retry or skip

**Option 3: Skip**
- Set `venafi.enabled = false` in config
- Print message: "You can configure Venafi later by editing config/cipherflag.toml"

## Step 4: Deploy

### Generate files

Write three files to the install directory:

**`docker-compose.yml`** — embedded template with:
- PostgreSQL 15 service with auto-generated password
- Zeek service with the selected network interface
- CipherFlag service with port 8443 exposed
- Named volumes for data persistence

**`.env`** — contains:
- `NETWORK_INTERFACE` — selected interface
- `POSTGRES_PASSWORD` — randomly generated 16-char alphanumeric
- Venafi environment variables (if configured)

**`config/cipherflag.toml`** — populated with:
- Server listen address
- PostgreSQL connection string (using generated password)
- Venafi configuration (platform, credentials, or disabled)
- Default analysis and source settings

### Pull images

Run `docker compose pull` in the install directory. Show progress to the user.

### Start services

Prompt: "Start services now? [Y/n]"

If yes, run `docker compose up -d` in the install directory. Verify services are running with `docker compose ps`. Print the dashboard URL using the selected interface's IP address.

If no, print instructions: "To start later, run: cd {dir} && docker compose up -d"

## Summary Output

After completion, print a summary box:

```
══════════════════════════════════════
Dashboard:  http://{ip}:8443
Venafi:     {platform} ({region}) — push every 60 min
Interface:  {name} ({ip})
Config:     {dir}/config/cipherflag.toml
══════════════════════════════════════
```

## Implementation

### Files

| File | Action | Responsibility |
|------|--------|----------------|
| `cmd/cipherflag/setup.go` | Create | Wizard logic, prompts, file generation |
| `cmd/cipherflag/setup_templates.go` | Create | Embedded templates for docker-compose.yml, .env, cipherflag.toml |
| `cmd/cipherflag/main.go` | Modify | Add `setup` case to command switch |
| `go.mod` | Modify | Add `golang.org/x/term` dependency |

### Terminal Input

- `bufio.Scanner` for text prompts
- `golang.org/x/term.ReadPassword` for masked input (API key, refresh token)
- Simple `prompt(question, defaultValue) string` helper
- Simple `promptChoice(question, options, defaultIndex) int` helper
- No external TUI libraries — keep it minimal

### Embedded Templates

Use `//go:embed` to embed template files. Templates use Go's `text/template` with placeholders:

```go
//go:embed templates/docker-compose.yml.tmpl
var dockerComposeTmpl string

//go:embed templates/env.tmpl
var envTmpl string

//go:embed templates/cipherflag.toml.tmpl
var tomlTmpl string
```

Template data struct:

```go
type SetupConfig struct {
    NetworkInterface string
    PostgresPassword string
    InterfaceIP      string
    // Venafi
    VenafiEnabled    bool
    VenafiPlatform   string // "cloud" or "tpp"
    VenafiAPIKey     string
    VenafiRegion     string
    VenafiBaseURL    string
    VenafiClientID   string
    VenafiRefreshToken string
    VenafiFolder     string
}
```

### Password Generation

Generate a random 16-character alphanumeric password using `crypto/rand`:

```go
func generatePassword(length int) string
```

### Docker Commands

Execute Docker commands via `os/exec`:

```go
func runDocker(dir string, args ...string) error
```

Commands run with working directory set to the install directory. Stdout/stderr piped to the terminal for progress visibility.

## Error Handling

- Pre-flight failure: clear message with install URL, exit code 1
- Interface listing failure: "No network interfaces found" with troubleshooting hint
- Venafi validation failure: show specific error, offer retry or skip
- Docker pull failure: show error, files are still written so user can retry manually
- Docker start failure: show error, print manual start instructions

## Dependencies

- `golang.org/x/term` — for masked password input
- No other new dependencies

## Out of Scope

- GUI/TUI (no `bubbletea`, `tview`, etc.)
- Automatic Docker installation
- Kubernetes deployment
- SSL/TLS for the CipherFlag dashboard itself
- Updating an existing installation (this is first-time setup only)
