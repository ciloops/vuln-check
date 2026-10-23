package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	MinVersion    = "0.87.0"
	EnvBinary     = "VULN_CHECK_GRYPE"
	defaultBinary = "grype"
)

var ErrNotInstalled = errors.New("grype not found in PATH; install: https://github.com/anchore/grype#installation")

type Result struct {
	Document  Document
	Inventory CycloneDX
	Version   string
}

type Runner struct {
	Binary string
	Env    []string
}

func NewRunner(binary string) *Runner {
	if binary == "" {
		binary = os.Getenv(EnvBinary)
	}
	if binary == "" {
		binary = defaultBinary
	}
	return &Runner{Binary: binary, Env: []string{"GRYPE_CHECK_FOR_APP_UPDATE=false"}}
}

func (r *Runner) Resolve() (string, error) {
	p, err := exec.LookPath(r.Binary)
	if err != nil {
		return "", ErrNotInstalled
	}
	return p, nil
}

func (r *Runner) exec(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := r.Resolve()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), r.Env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("grype %s: %w", args[0], ctx.Err())
		}
		return nil, fmt.Errorf("grype %s: %w: %s", args[0], err, lastLines(stderr.String(), 5))
	}
	return stdout.Bytes(), nil
}

func (r *Runner) Version(ctx context.Context) (string, error) {
	out, err := r.exec(ctx, "version", "-o", "json")
	if err != nil {
		return "", err
	}
	var v VersionInfo
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("parse grype version: %w", err)
	}
	return v.Version, nil
}

// Scan runs grype once on target, producing the rich JSON document and a
// CycloneDX SBOM so the full inventory is available to overlays.
func (r *Runner) Scan(ctx context.Context, target string) (*Result, error) {
	dir, err := os.MkdirTemp("", "vuln-check-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	jsonPath := filepath.Join(dir, "grype.json")
	cdxPath := filepath.Join(dir, "sbom.cdx.json")
	args := []string{target, "-q",
		"-o", "json=" + jsonPath,
		"-o", "cyclonedx-json=" + cdxPath,
	}
	if _, err := r.exec(ctx, args...); err != nil {
		return nil, err
	}
	res := &Result{}
	if err := readJSON(jsonPath, &res.Document); err != nil {
		return nil, fmt.Errorf("read grype json: %w", err)
	}
	if err := readJSON(cdxPath, &res.Inventory); err != nil {
		return nil, fmt.Errorf("read grype sbom: %w", err)
	}
	res.Version = res.Document.Descriptor.Version
	return res, nil
}

func (r *Runner) DBUpdate(ctx context.Context) (string, error) {
	out, err := r.exec(ctx, "db", "update")
	return strings.TrimSpace(string(out)), err
}

func (r *Runner) DBStatus(ctx context.Context) (string, error) {
	out, err := r.exec(ctx, "db", "status")
	return strings.TrimSpace(string(out)), err
}

func (r *Runner) VulnLookup(ctx context.Context, id string) (json.RawMessage, error) {
	out, err := r.exec(ctx, "db", "search", "vuln", id, "-o", "json")
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(out)), nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
