package score

import (
	"testing"

	"github.com/ciloops/vuln-check/internal/model"
)

func TestCompute(t *testing.T) {
	fixed := []string{"1.0.1"}
	cases := []struct {
		name string
		f    model.Finding
		want int
	}{
		{"critical cvss with fix", model.Finding{CVSS: 9.8, EPSS: 0.5, FixVersions: fixed, FixState: model.FixStateFixed}, 74},
		{"kev floors at 85", model.Finding{CVSS: 5.0, EPSS: 0.01, KEV: true, FixVersions: fixed, FixState: model.FixStateFixed}, 85},
		{"kev adds on top when already high", model.Finding{CVSS: 10, EPSS: 0.9, KEV: true, FixVersions: fixed, FixState: model.FixStateFixed}, 97},
		{"label fallback high", model.Finding{Severity: model.SeverityHigh, FixVersions: fixed, FixState: model.FixStateFixed}, 42},
		{"no fix penalised", model.Finding{CVSS: 7.2, EPSS: 0.1, FixState: model.FixStateNotFixed}, 39},
		{"wont fix penalised even with versions", model.Finding{CVSS: 7.2, EPSS: 0.1, FixVersions: fixed, FixState: model.FixStateWontFix}, 39},
		{"unknown everything", model.Finding{FixState: model.FixStateUnknown}, 9},
		{"clamped at 100", model.Finding{CVSS: 10, EPSS: 1, KEV: true, FixVersions: fixed, FixState: model.FixStateFixed}, 100},
	}
	for _, c := range cases {
		if got := Compute(c.f); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestApplyOrdersNothing(t *testing.T) {
	fs := []model.Finding{{CVSS: 1}, {CVSS: 9}}
	Apply(fs)
	if fs[0].Score == 0 || fs[1].Score == 0 || fs[0].Score > fs[1].Score {
		t.Fatalf("scores = %d %d", fs[0].Score, fs[1].Score)
	}
}
