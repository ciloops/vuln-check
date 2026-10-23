package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ciloops/vuln-check/internal/grype"
)

func useFakeGrype(t *testing.T) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "fake-grype.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "grype")
	if err := os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures, _ := filepath.Abs(filepath.Join("..", "..", "internal", "grype", "testdata"))
	t.Setenv(grype.EnvBinary, bin)
	t.Setenv("FIXTURES", fixtures)
}

func TestScanAgentFormat(t *testing.T) {
	useFakeGrype(t)
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--no-osv", "--top", "1", "/work/app"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var a map[string]any
	if err := json.Unmarshal(out.Bytes(), &a); err != nil {
		t.Fatalf("not json: %s", out.String())
	}
	if a["status"] != "ACTION_REQUIRED" || a["shown"].(float64) != 1 {
		t.Fatalf("report = %s", out.String())
	}
}

func TestScanFailAbove(t *testing.T) {
	useFakeGrype(t)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--no-osv", "--fail-above", "80", "."}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, errb.String())
	}
	if code := run([]string{"scan", "--no-osv", "--fail-above", "100", "."}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
}

func TestScanSARIFAndFull(t *testing.T) {
	useFakeGrype(t)
	for _, format := range []string{"sarif", "full"} {
		var out, errb bytes.Buffer
		if code := run([]string{"scan", "--no-osv", "--format", format, "."}, &out, &errb); code != 0 {
			t.Fatalf("%s exit %d: %s", format, code, errb.String())
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("%s output is not valid json", format)
		}
	}
}

func TestMissingGrype(t *testing.T) {
	t.Setenv(grype.EnvBinary, filepath.Join(t.TempDir(), "nope"))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--no-osv", "."}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "grype not found") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

func TestDBAndVulnCommands(t *testing.T) {
	useFakeGrype(t)
	var out, errb bytes.Buffer
	if code := run([]string{"db", "update"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "updated") {
		t.Fatalf("db update: %d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"vuln", "CVE-2021-23337"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "CVE-2021-23337") {
		t.Fatalf("vuln: %d %s %s", code, out.String(), errb.String())
	}
}

func TestVersionAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatalf("version: %d %q", code, out.String())
	}
	if code := run(nil, &out, &errb); code != 1 || !strings.Contains(errb.String(), "Usage") {
		t.Fatalf("usage: %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errb); code != 1 {
		t.Fatalf("bogus: %d", code)
	}
}
