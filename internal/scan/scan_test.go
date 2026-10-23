package scan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ciloops/vuln-check/internal/grype"
	"github.com/ciloops/vuln-check/internal/model"
)

type fakeGrype struct {
	res    *grype.Result
	target string
}

func (f *fakeGrype) Scan(_ context.Context, target string) (*grype.Result, error) {
	f.target = target
	return f.res, nil
}

type fakeOverlay struct {
	known map[string]bool
	inv   int
	err   error
}

func (f *fakeOverlay) Overlay(_ context.Context, inventory []model.Package, known map[string]bool) ([]model.Finding, error) {
	f.known, f.inv = known, len(inventory)
	if f.err != nil {
		return nil, f.err
	}
	return []model.Finding{{ID: "GHSA-fresh", Package: inventory[0], Severity: model.SeverityHigh, FixVersions: []string{"9"}, FixState: model.FixStateFixed, Fresh: true, Sources: []string{model.SourceOSV}}}, nil
}

func fixture(t *testing.T) *grype.Result {
	t.Helper()
	res := &grype.Result{}
	for name, dst := range map[string]any{"grype.json": &res.Document, "sbom.cdx.json": &res.Inventory} {
		b, err := os.ReadFile(filepath.Join("..", "grype", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

func TestRunMergesOverlayAndScores(t *testing.T) {
	g := &fakeGrype{res: fixture(t)}
	o := &fakeOverlay{}
	s := &Scanner{Grype: g, Overlay: o}
	res, err := s.Run(context.Background(), Options{Target: "image:python:3.12", OSV: true})
	if err != nil {
		t.Fatal(err)
	}
	if g.target != "image:python:3.12" {
		t.Errorf("target passed = %q", g.target)
	}
	if o.inv != 6 || !o.known["CVE-2021-23337"] || !o.known["GHSA-35jh-r3h4-6jhm"] {
		t.Errorf("overlay got inv=%d known=%v", o.inv, o.known)
	}
	if len(res.Scan.Findings) != 5 || len(res.Scan.Sources) != 2 {
		t.Fatalf("findings=%d sources=%v", len(res.Scan.Findings), res.Scan.Sources)
	}
	for _, f := range res.Scan.Findings {
		if f.Score == 0 {
			t.Errorf("%s not scored", f.ID)
		}
	}
	if len(res.Plan) == 0 || res.Plan[0].Name != "liblzma5" {
		t.Errorf("plan top should be the KEV package: %+v", res.Plan)
	}
}

func TestRunOverlayFailureIsWarning(t *testing.T) {
	s := &Scanner{Grype: &fakeGrype{res: fixture(t)}, Overlay: &fakeOverlay{err: errors.New("boom")}}
	res, err := s.Run(context.Background(), Options{Target: ".", OSV: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Scan.Findings) != 4 || len(res.Scan.Warnings) != 1 || len(res.Scan.Sources) != 1 {
		t.Fatalf("scan = %+v", res.Scan)
	}
}

func TestRunWithoutOSV(t *testing.T) {
	o := &fakeOverlay{}
	s := &Scanner{Grype: &fakeGrype{res: fixture(t)}, Overlay: o}
	if _, err := s.Run(context.Background(), Options{Target: ".", OSV: false}); err != nil {
		t.Fatal(err)
	}
	if o.inv != 0 {
		t.Fatal("overlay must not run when disabled")
	}
}

func TestNormalizeTarget(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "bom.json")
	os.WriteFile(sbom, []byte("{}"), 0o644)
	bin := filepath.Join(dir, "app")
	os.WriteFile(bin, []byte("x"), 0o644)
	cases := map[string]string{
		"":                    "dir:.",
		dir:                   "dir:" + dir,
		sbom:                  "sbom:" + sbom,
		bin:                   "file:" + bin,
		"python:3.12":         "python:3.12",
		"sbom:./x.json":       "sbom:./x.json",
		"registry:alpine:3.2": "registry:alpine:3.2",
	}
	for in, want := range cases {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
