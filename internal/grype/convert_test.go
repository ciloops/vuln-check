package grype

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ciloops/vuln-check/internal/model"
)

func LoadFixture(t testing.TB) *Result {
	t.Helper()
	res := &Result{}
	for name, dst := range map[string]any{"grype.json": &res.Document, "sbom.cdx.json": &res.Inventory} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	res.Version = res.Document.Descriptor.Version
	return res
}

func TestToScan(t *testing.T) {
	sc := ToScan("dir:/work/app", LoadFixture(t))

	if sc.Packages != 6 {
		t.Fatalf("packages = %d, want 6 (operating-system component excluded)", sc.Packages)
	}
	if len(sc.Findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(sc.Findings))
	}
	if sc.Distro != "ubuntu 24.04" || sc.GrypeVersion != "0.100.0" || sc.DBBuilt != "2026-10-22T01:31:12Z" {
		t.Fatalf("metadata = %q %q %q", sc.Distro, sc.GrypeVersion, sc.DBBuilt)
	}

	byID := map[string]model.Finding{}
	for _, f := range sc.Findings {
		byID[f.ID] = f
	}

	lodash := byID["CVE-2021-23337"]
	if lodash.CVSS != 7.2 || lodash.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("lodash cvss: prefers Primary 3.1, got %v %q", lodash.CVSS, lodash.CVSSVector)
	}
	if len(lodash.Aliases) != 1 || lodash.Aliases[0] != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("lodash aliases = %v", lodash.Aliases)
	}
	if lodash.EPSS != 0.0041 || lodash.Severity != model.SeverityHigh || lodash.FixState != model.FixStateFixed {
		t.Errorf("lodash fields = %+v", lodash)
	}
	if len(lodash.FixVersions) != 1 || lodash.FixVersions[0] != "4.17.21" {
		t.Errorf("suggestedVersion must not duplicate fix version: %v", lodash.FixVersions)
	}
	if lodash.Package.PURL != "pkg:npm/lodash@4.17.20" || lodash.Package.Locations[0] != "/package-lock.json" {
		t.Errorf("package = %+v", lodash.Package)
	}

	xz := byID["CVE-2024-3094"]
	if !xz.KEV || xz.CVSS != 10 || xz.Package.Type != "deb" {
		t.Errorf("xz = %+v", xz)
	}

	nofix := byID["GHSA-fake-nofix-0001"]
	if nofix.HasFix() || nofix.FixState != model.FixStateNotFixed || nofix.Severity != model.SeverityMedium {
		t.Errorf("nofix = %+v", nofix)
	}
}

func TestInventoryFallsBackToMatches(t *testing.T) {
	res := LoadFixture(t)
	res.Inventory = CycloneDX{}
	sc := ToScan("dir:x", res)
	if sc.Packages != 4 {
		t.Fatalf("packages = %d, want 4 from matches", sc.Packages)
	}
}

func TestPackageKey(t *testing.T) {
	p := model.Package{PURL: "pkg:deb/ubuntu/liblzma5@5.6.0-0.2?arch=amd64", Name: "liblzma5", Type: "deb"}
	if got := p.Key(); got != "pkg:deb/ubuntu/liblzma5" {
		t.Fatalf("key = %q", got)
	}
	if got := (model.Package{Name: "x", Type: "npm"}).Key(); got != "npm/x" {
		t.Fatalf("key without purl = %q", got)
	}
}
