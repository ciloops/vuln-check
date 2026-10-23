package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ciloops/vuln-check/internal/model"
	"github.com/ciloops/vuln-check/internal/remediate"
)

func sampleScan() *model.Scan {
	return &model.Scan{
		Target: "dir:.", Packages: 40, Sources: []string{"grype", "osv"},
		Findings: []model.Finding{
			{ID: "CVE-1", Package: model.Package{Name: "a", Version: "1.0", PURL: "pkg:npm/a@1.0", Locations: []string{"/package-lock.json"}}, Severity: model.SeverityHigh, CVSS: 7.5, Score: 55, FixVersions: []string{"1.1"}, FixState: "fixed", Description: strings.Repeat("x", 300)},
			{ID: "CVE-2", Package: model.Package{Name: "b", Version: "2.0", PURL: "pkg:npm/b@2.0"}, Severity: model.SeverityCritical, Score: 95, KEV: true, EPSS: 0.91234, FixVersions: []string{"2.1"}, FixState: "fixed"},
			{ID: "CVE-3", Package: model.Package{Name: "c", Version: "3.0", PURL: "pkg:npm/c@3.0"}, Severity: model.SeverityLow, Score: 12, FixState: "not-fixed"},
		},
	}
}

func TestBuildAgentActionRequired(t *testing.T) {
	sc := sampleScan()
	plan := remediate.Plan(sc.Findings)
	opts := DefaultOptions()
	opts.Top = 2
	a := BuildAgent(sc, plan, opts)

	if a.Status != StatusActionRequired || a.Findings != 3 || a.Shown != 2 || a.Packages != 40 {
		t.Fatalf("agent = %+v", a)
	}
	if a.Top[0].ID != "CVE-2" || !a.Top[0].Exploited || a.Top[0].EPSS != 0.912 {
		t.Errorf("top[0] = %+v", a.Top[0])
	}
	if a.Top[1].ID != "CVE-1" || len(a.Top[1].Summary) > 125 || !strings.HasSuffix(a.Top[1].Summary, "…") {
		t.Errorf("top[1] = %+v", a.Top[1])
	}
	if len(a.Actions) != 2 || a.Actions[0].Package != "pkg:npm/b" || a.Actions[0].Target != "2.1" {
		t.Errorf("actions = %+v", a.Actions)
	}
	if a.Unfixable != 1 {
		t.Errorf("unfixable = %d", a.Unfixable)
	}
	var round map[string]any
	if err := json.Unmarshal(a.JSON(), &round); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAgentClean(t *testing.T) {
	sc := &model.Scan{Target: "dir:.", Packages: 12, Sources: []string{"grype"}}
	a := BuildAgent(sc, nil, DefaultOptions())
	if a.Status != StatusClean || len(a.Top) != 0 || len(a.Actions) != 0 {
		t.Fatalf("agent = %+v", a)
	}
	if n := len(a.JSON()); n > 90 {
		t.Fatalf("clean report should be tiny, got %d bytes: %s", n, a.JSON())
	}
}

func TestBuildAgentReview(t *testing.T) {
	sc := sampleScan()
	sc.Findings = sc.Findings[2:]
	a := BuildAgent(sc, remediate.Plan(sc.Findings), DefaultOptions())
	if a.Status != StatusReview {
		t.Fatalf("status = %s", a.Status)
	}
}

func TestBuildSARIF(t *testing.T) {
	sc := sampleScan()
	b := BuildSARIF(sc, "1.2.3")
	var log map[string]any
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results = %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["ruleId"] != "CVE-1" || first["level"] != "error" {
		t.Errorf("first = %v", first)
	}
	loc := first["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
	if loc != "package-lock.json" {
		t.Errorf("uri = %v", loc)
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Errorf("rules = %d", len(rules))
	}
	empty := BuildSARIF(&model.Scan{}, "x")
	if !strings.Contains(string(empty), `"results": []`) {
		t.Errorf("empty scan must emit an empty results array")
	}
}

func TestBuildFull(t *testing.T) {
	sc := sampleScan()
	f := BuildFull(sc, remediate.Plan(sc.Findings), DefaultOptions())
	if f.Status != StatusActionRequired || len(f.Plan) != 3 {
		t.Fatalf("full = %+v", f)
	}
}
