package remediate

import (
	"sort"

	"github.com/ciloops/vuln-check/internal/model"
	"github.com/ciloops/vuln-check/internal/version"
)

type Action struct {
	Package  string   `json:"package"`
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Current  string   `json:"current"`
	Target   string   `json:"target,omitempty"`
	Breaking bool     `json:"breaking"`
	Fixes    []string `json:"fixes,omitempty"`
	Unfixed  []string `json:"unfixed,omitempty"`
	Score    int      `json:"score"`
}

// Plan groups findings by package and picks, per package, the smallest
// version that closes every finding with a fix above the current version.
// Findings whose fixes are all on another release line stay in Unfixed.
func Plan(findings []model.Finding) []Action {
	groups := map[string][]model.Finding{}
	var order []string
	for _, f := range findings {
		k := f.Package.Key() + "@" + f.Package.Version
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}
	var out []Action
	for _, k := range order {
		if a := plan(groups[k]); a != nil {
			out = append(out, *a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func plan(fs []model.Finding) *Action {
	p := fs[0].Package
	a := &Action{Package: p.Key(), Name: p.Name, Type: p.Type, Current: p.Version}
	for _, f := range fs {
		if f.Score > a.Score {
			a.Score = f.Score
		}
		if mf := minFixAbove(f.FixVersions, p.Version); mf != "" {
			if a.Target == "" || version.Less(a.Target, mf) {
				a.Target = mf
			}
		}
	}
	for _, f := range fs {
		if a.Target != "" && fixedBy(f.FixVersions, p.Version, a.Target) {
			a.Fixes = append(a.Fixes, f.ID)
		} else {
			a.Unfixed = append(a.Unfixed, f.ID)
		}
	}
	if a.Target != "" {
		a.Breaking = version.Breaking(p.Version, a.Target, p.Type)
	}
	return a
}

func minFixAbove(fixes []string, current string) string {
	best := ""
	for _, v := range fixes {
		if !version.Less(current, v) {
			continue
		}
		if best == "" || version.Less(v, best) {
			best = v
		}
	}
	return best
}

func fixedBy(fixes []string, current, target string) bool {
	for _, v := range fixes {
		if version.Less(current, v) && version.Compare(v, target) <= 0 {
			return true
		}
	}
	return false
}
