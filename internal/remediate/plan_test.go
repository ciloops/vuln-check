package remediate

import (
	"testing"

	"github.com/ciloops/vuln-check/internal/model"
)

func pkg(name, ver, typ string) model.Package {
	return model.Package{Name: name, Version: ver, Type: typ, PURL: "pkg:" + typ + "/" + name + "@" + ver}
}

func TestPlanPicksMinimalTargetCoveringAll(t *testing.T) {
	fs := []model.Finding{
		{ID: "A", Package: pkg("lodash", "4.17.15", "npm"), FixVersions: []string{"4.17.19"}, Score: 50},
		{ID: "B", Package: pkg("lodash", "4.17.15", "npm"), FixVersions: []string{"4.17.21"}, Score: 70},
		{ID: "C", Package: pkg("lodash", "4.17.15", "npm"), FixVersions: []string{"4.17.12"}, Score: 10},
	}
	plan := Plan(fs)
	if len(plan) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	a := plan[0]
	if a.Target != "4.17.21" || a.Breaking || a.Score != 70 {
		t.Fatalf("action = %+v", a)
	}
	if len(a.Fixes) != 2 || len(a.Unfixed) != 1 || a.Unfixed[0] != "C" {
		t.Fatalf("fixes=%v unfixed=%v", a.Fixes, a.Unfixed)
	}
}

func TestPlanBreakingAndUnfixable(t *testing.T) {
	fs := []model.Finding{
		{ID: "X", Package: pkg("express", "4.19.2", "npm"), FixVersions: []string{"5.0.0"}, Score: 60},
		{ID: "Y", Package: pkg("debug", "4.3.4", "npm"), FixState: model.FixStateNotFixed, Score: 20},
		{ID: "Z", Package: pkg("minimist", "1.2.5", "npm"), FixVersions: []string{"1.2.6", "0.2.4"}, Score: 90},
	}
	plan := Plan(fs)
	if len(plan) != 3 {
		t.Fatalf("plan len = %d", len(plan))
	}
	if plan[0].Name != "minimist" || plan[0].Target != "1.2.6" || plan[0].Breaking {
		t.Errorf("minimist = %+v", plan[0])
	}
	if plan[1].Name != "express" || plan[1].Target != "5.0.0" || !plan[1].Breaking {
		t.Errorf("express = %+v", plan[1])
	}
	if plan[2].Name != "debug" || plan[2].Target != "" || len(plan[2].Unfixed) != 1 {
		t.Errorf("debug = %+v", plan[2])
	}
}

func TestPlanOtherReleaseLineStaysUnfixed(t *testing.T) {
	fs := []model.Finding{
		{ID: "OLD", Package: pkg("lib", "2.0.0", "pypi"), FixVersions: []string{"1.9.9"}, Score: 30},
	}
	plan := Plan(fs)
	if plan[0].Target != "" || len(plan[0].Unfixed) != 1 {
		t.Fatalf("action = %+v", plan[0])
	}
}
