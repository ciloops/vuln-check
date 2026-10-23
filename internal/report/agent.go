package report

import (
	"encoding/json"
	"sort"

	"github.com/ciloops/vuln-check/internal/model"
	"github.com/ciloops/vuln-check/internal/remediate"
)

const (
	StatusClean          = "CLEAN"
	StatusActionRequired = "ACTION_REQUIRED"
	StatusReview         = "REVIEW"
)

type Options struct {
	Top             int
	MaxActions      int
	ActionThreshold int
}

func DefaultOptions() Options {
	return Options{Top: 10, MaxActions: 10, ActionThreshold: 40}
}

type Agent struct {
	Status    string         `json:"status"`
	Target    string         `json:"target"`
	Packages  int            `json:"packages"`
	Findings  int            `json:"findings,omitempty"`
	Shown     int            `json:"shown,omitempty"`
	Sources   []string       `json:"sources"`
	Actions   []AgentAction  `json:"actions,omitempty"`
	Top       []AgentFinding `json:"top,omitempty"`
	Unfixable int            `json:"unfixable,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
}

type AgentAction struct {
	Package  string   `json:"package"`
	Current  string   `json:"current"`
	Target   string   `json:"target,omitempty"`
	Breaking bool     `json:"breaking"`
	Fixes    []string `json:"fixes,omitempty"`
	Unfixed  []string `json:"unfixed,omitempty"`
	Score    int      `json:"score"`
}

type AgentFinding struct {
	ID        string   `json:"id"`
	Package   string   `json:"package"`
	Severity  string   `json:"severity"`
	Score     int      `json:"score"`
	Exploited bool     `json:"exploited,omitempty"`
	EPSS      float64  `json:"epss,omitempty"`
	FixedIn   []string `json:"fixed_in,omitempty"`
	Fresh     bool     `json:"fresh,omitempty"`
	Summary   string   `json:"summary,omitempty"`
}

func BuildAgent(scan *model.Scan, plan []remediate.Action, opts Options) Agent {
	out := Agent{
		Target:   scan.Target,
		Packages: scan.Packages,
		Sources:  scan.Sources,
		Warnings: scan.Warnings,
		Findings: len(scan.Findings),
	}
	if len(scan.Findings) == 0 {
		out.Status = StatusClean
		return out
	}
	sorted := append([]model.Finding(nil), scan.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Score > sorted[j].Score })

	out.Status = StatusReview
	if sorted[0].Score >= opts.ActionThreshold {
		out.Status = StatusActionRequired
	}
	for _, f := range sorted {
		if len(out.Top) >= opts.Top {
			break
		}
		out.Top = append(out.Top, toAgentFinding(f))
	}
	out.Shown = len(out.Top)
	for _, a := range plan {
		if a.Target == "" {
			out.Unfixable += len(a.Unfixed)
			continue
		}
		if len(out.Actions) >= opts.MaxActions {
			continue
		}
		out.Actions = append(out.Actions, AgentAction{
			Package: a.Package, Current: a.Current, Target: a.Target, Breaking: a.Breaking,
			Fixes: a.Fixes, Unfixed: a.Unfixed, Score: a.Score,
		})
	}
	return out
}

func toAgentFinding(f model.Finding) AgentFinding {
	return AgentFinding{
		ID:        f.ID,
		Package:   f.Package.Name + "@" + f.Package.Version,
		Severity:  string(f.Severity),
		Score:     f.Score,
		Exploited: f.KEV,
		EPSS:      round3(f.EPSS),
		FixedIn:   f.FixVersions,
		Fresh:     f.Fresh,
		Summary:   truncate(f.Description, 120),
	}
}

func (a Agent) JSON() []byte {
	b, _ := json.Marshal(a)
	return b
}

func round3(x float64) float64 {
	return float64(int(x*1000+0.5)) / 1000
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
