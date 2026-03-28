package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"

	"golang.org/x/term"

	"github.com/cyberflag-ai/cipherflag/internal/export/venafi"
)

// SetupConfig holds all wizard-collected values for template rendering.
type SetupConfig struct {
	NetworkInterface   string
	InterfaceIP        string
	PostgresPassword   string
	VenafiEnabled      bool
	VenafiPlatform     string
	VenafiAPIKey       string
	VenafiRegion       string
	VenafiBaseURL      string
	VenafiClientID     string
	VenafiRefreshToken string
	VenafiFolder       string
}

var scanner *bufio.Scanner

func runSetup() {
	scanner = bufio.NewScanner(os.Stdin)

	fmt.Println()
	fmt.Println("  CipherFlag Setup")
	fmt.Println("  ─────────────────")
	fmt.Println()

	// Pre-flight checks
	if !checkPrereqs() {
		os.Exit(1)
	}

	cfg := SetupConfig{
		PostgresPassword: generatePassword(16),
		VenafiFolder:     `\VED\Policy\Discovered\CipherFlag`,
		VenafiRegion:     "us",
	}

	// Step 1: Installation directory
	dir := promptInstallDir()

	// Step 2: Network interface
	iface, ip := promptNetworkInterface()
	cfg.NetworkInterface = iface
	cfg.InterfaceIP = ip

	// Step 3: Venafi
	promptVenafi(&cfg)

	// Step 4: Generate files
	fmt.Println()
	if err := generateFiles(dir, &cfg); err != nil {
		fmt.Printf("  ✗ Failed to generate files: %v\n", err)
		os.Exit(1)
	}

	// Pull images
	fmt.Println()
	fmt.Println("  Pulling images...")
	if err := runDocker(dir, "compose", "pull"); err != nil {
		fmt.Printf("  ✗ Image pull failed: %v\n", err)
		fmt.Printf("  Files written to %s — you can retry with: cd %s && docker compose pull\n", dir, dir)
	} else {
		fmt.Println("  ✓ Images pulled")
	}

	// Start services
	fmt.Println()
	if promptYN("  Start services now?", true) {
		fmt.Println()
		if err := runDocker(dir, "compose", "up", "-d"); err != nil {
			fmt.Printf("  ✗ Failed to start: %v\n", err)
			fmt.Printf("  Try manually: cd %s && docker compose up -d\n", dir)
		} else {
			fmt.Println("  ✓ Services started")
		}
	} else {
		fmt.Printf("\n  To start later: cd %s && docker compose up -d\n", dir)
	}

	// Summary
	fmt.Println()
	fmt.Println("  ══════════════════════════════════════")
	fmt.Printf("  Dashboard:  http://%s:8443\n", cfg.InterfaceIP)
	if cfg.VenafiEnabled {
		if cfg.VenafiPlatform == "cloud" {
			fmt.Printf("  Venafi:     Cloud (%s) — push every 60 min\n", cfg.VenafiRegion)
		} else {
			fmt.Printf("  Venafi:     TPP (%s) — push every 60 min\n", cfg.VenafiBaseURL)
		}
	} else {
		fmt.Println("  Venafi:     Not configured")
	}
	fmt.Printf("  Interface:  %s (%s)\n", cfg.NetworkInterface, cfg.InterfaceIP)
	fmt.Printf("  Config:     %s/config/cipherflag.toml\n", dir)
	fmt.Println("  ══════════════════════════════════════")
	fmt.Println()
}

// ── Pre-flight ──────────────────────────────────────────────────────────────

func checkPrereqs() bool {
	fmt.Println("  Pre-flight checks...")

	dockerOut, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		fmt.Println("  ✗ Docker not found")
		fmt.Println("    Install Docker: https://docs.docker.com/get-docker/")
		return false
	}
	fmt.Printf("  ✓ Docker %s\n", strings.TrimSpace(string(dockerOut)))

	composeOut, err := exec.Command("docker", "compose", "version", "--short").Output()
	if err != nil {
		fmt.Println("  ✗ Docker Compose not found")
		fmt.Println("    Install Docker Compose: https://docs.docker.com/compose/install/")
		return false
	}
	fmt.Printf("  ✓ Docker Compose %s\n", strings.TrimSpace(string(composeOut)))

	return true
}

// ── Step 1: Directory ───────────────────────────────────────────────────────

func promptInstallDir() string {
	fmt.Println()
	fmt.Println("  Step 1/4: Installation Directory")
	dir := prompt("  Directory", "./cipherflag")

	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}

	if info, err := os.Stat(absDir); err == nil && info.IsDir() {
		if _, err := os.Stat(filepath.Join(absDir, "docker-compose.yml")); err == nil {
			if !promptYN("  Directory already contains docker-compose.yml. Overwrite?", false) {
				fmt.Println("  Setup cancelled.")
				os.Exit(0)
			}
		}
	}

	if err := os.MkdirAll(filepath.Join(absDir, "config"), 0755); err != nil {
		fmt.Printf("  ✗ Failed to create directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Using %s\n", absDir)

	return absDir
}

// ── Step 2: Network Interface ───────────────────────────────────────────────

type ifaceInfo struct {
	Name       string
	IP         string
	IsUp       bool
	IsLoopback bool
}

func listInterfaces() []ifaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []ifaceInfo
	for _, iface := range ifaces {
		info := ifaceInfo{
			Name:       iface.Name,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					info.IP = ipnet.IP.String()
					break
				}
			}
		}

		if info.IP != "" {
			result = append(result, info)
		}
	}
	return result
}

func promptNetworkInterface() (string, string) {
	fmt.Println()
	fmt.Println("  Step 2/4: Network Capture")

	ifaces := listInterfaces()
	if len(ifaces) == 0 {
		fmt.Println("  ✗ No network interfaces found")
		os.Exit(1)
	}

	fmt.Println("  Available interfaces:")
	for i, iface := range ifaces {
		status := "up"
		if !iface.IsUp {
			status = "down"
		}
		suffix := ""
		if iface.IsLoopback {
			suffix = " (loopback)"
		}
		fmt.Printf("    %d. %-14s %-16s %s%s\n", i+1, iface.Name, iface.IP, status, suffix)
	}

	choice := promptChoice("  Select interface", len(ifaces), 1)
	selected := ifaces[choice-1]
	fmt.Printf("  ✓ Using %s (%s)\n", selected.Name, selected.IP)
	return selected.Name, selected.IP
}

// ── Step 3: Venafi ──────────────────────────────────────────────────────────

func promptVenafi(cfg *SetupConfig) {
	fmt.Println()
	fmt.Println("  Step 3/4: Venafi Integration")
	fmt.Println("    1. Venafi Cloud (SaaS)")
	fmt.Println("    2. Venafi TPP (on-prem)")
	fmt.Println("    3. Skip (configure later)")

	choice := promptChoice("  Select", 3, 1)

	switch choice {
	case 1:
		promptVenafiCloud(cfg)
	case 2:
		promptVenafiTPP(cfg)
	case 3:
		cfg.VenafiEnabled = false
		fmt.Println("  ✓ Venafi skipped — configure later in config/cipherflag.toml")
	}
}

func promptVenafiCloud(cfg *SetupConfig) {
	cfg.VenafiEnabled = true
	cfg.VenafiPlatform = "cloud"

	fmt.Print("  API key: ")
	apiKeyBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("  ✗ Failed to read API key: %v\n", err)
		cfg.VenafiEnabled = false
		return
	}
	cfg.VenafiAPIKey = strings.TrimSpace(string(apiKeyBytes))

	if cfg.VenafiAPIKey == "" {
		fmt.Println("  ✗ Empty API key — skipping Venafi")
		cfg.VenafiEnabled = false
		return
	}

	cfg.VenafiRegion = prompt("  Region (us/eu)", "us")

	fmt.Print("  Validating...")
	client := venafi.NewCloudClient(cfg.VenafiRegion, cfg.VenafiAPIKey)
	if err := client.ValidateConnection(context.Background()); err != nil {
		fmt.Printf("\n  ✗ Connection failed: %v\n", err)
		if promptYN("  Skip Venafi and continue?", true) {
			cfg.VenafiEnabled = false
			return
		}
		promptVenafiCloud(cfg)
		return
	}
	fmt.Println(" ✓ Connected to Venafi Cloud")
}

func promptVenafiTPP(cfg *SetupConfig) {
	cfg.VenafiEnabled = true
	cfg.VenafiPlatform = "tpp"

	cfg.VenafiBaseURL = prompt("  TPP base URL (e.g., https://tpp.example.com)", "")
	if cfg.VenafiBaseURL == "" {
		fmt.Println("  ✗ Empty URL — skipping Venafi")
		cfg.VenafiEnabled = false
		return
	}

	cfg.VenafiClientID = prompt("  Client ID", "")

	fmt.Print("  Refresh token: ")
	tokenBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("  ✗ Failed to read token: %v\n", err)
		cfg.VenafiEnabled = false
		return
	}
	cfg.VenafiRefreshToken = strings.TrimSpace(string(tokenBytes))

	cfg.VenafiFolder = prompt("  Policy folder", `\VED\Policy\Discovered\CipherFlag`)

	fmt.Print("  Validating...")
	authBase := cfg.VenafiBaseURL + "/vedauth"
	sdkBase := cfg.VenafiBaseURL + "/vedsdk"
	tppClient := venafi.NewClient(sdkBase, authBase, cfg.VenafiClientID, cfg.VenafiRefreshToken)
	adapter := venafi.NewTPPAdapter(tppClient, cfg.VenafiFolder)
	if err := adapter.ValidateConnection(context.Background()); err != nil {
		fmt.Printf("\n  ✗ Connection failed: %v\n", err)
		if promptYN("  Skip Venafi and continue?", true) {
			cfg.VenafiEnabled = false
			return
		}
		promptVenafiTPP(cfg)
		return
	}
	fmt.Println(" ✓ Connected to Venafi TPP")
}

// ── Step 4: File Generation ─────────────────────────────────────────────────

func generateFiles(dir string, cfg *SetupConfig) error {
	files := []struct {
		tmpl string
		path string
	}{
		{dockerComposeTmpl, filepath.Join(dir, "docker-compose.yml")},
		{envTmpl, filepath.Join(dir, ".env")},
		{tomlTmpl, filepath.Join(dir, "config", "cipherflag.toml")},
	}

	for _, f := range files {
		t, err := template.New("").Parse(f.tmpl)
		if err != nil {
			return fmt.Errorf("parsing template for %s: %w", f.path, err)
		}

		file, err := os.Create(f.path)
		if err != nil {
			return fmt.Errorf("creating %s: %w", f.path, err)
		}

		if err := t.Execute(file, cfg); err != nil {
			file.Close()
			return fmt.Errorf("executing template for %s: %w", f.path, err)
		}
		file.Close()

		rel, _ := filepath.Rel(dir, f.path)
		fmt.Printf("  ✓ Wrote %s\n", rel)
	}

	return nil
}

// ── Docker Commands ─────────────────────────────────────────────────────────

func runDocker(dir string, args ...string) error {
	cmd := exec.Command("docker", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func prompt(question, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", question, defaultValue)
	} else {
		fmt.Printf("%s: ", question)
	}

	scanner.Scan()
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return defaultValue
	}
	return input
}

func promptChoice(question string, maxChoice, defaultChoice int) int {
	for {
		fmt.Printf("%s [%d]: ", question, defaultChoice)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			return defaultChoice
		}
		var choice int
		if _, err := fmt.Sscanf(input, "%d", &choice); err == nil && choice >= 1 && choice <= maxChoice {
			return choice
		}
		fmt.Printf("  Please enter 1-%d\n", maxChoice)
	}
}

func promptYN(question string, defaultYes bool) bool {
	suffix := "[Y/n]"
	if !defaultYes {
		suffix = "[y/N]"
	}
	fmt.Printf("%s %s: ", question, suffix)

	scanner.Scan()
	input := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "cipherflag-default-pw"
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
