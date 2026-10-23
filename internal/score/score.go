package score

import (
	"math"

	"github.com/ciloops/vuln-check/internal/model"
)

// Compute maps a finding to 0..100.
//
//	severity  CVSS base * 6 (0..60); label fallback when no CVSS
//	exploit   EPSS probability * 30 (0..30)
//	kev       +10 and floor at 85
//	no fix    * 0.85 (less actionable)
func Compute(f model.Finding) int {
	s := severityPoints(f)
	s += f.EPSS * 30
	if f.KEV {
		s += 10
		if s < 85 {
			s = 85
		}
	}
	if !f.HasFix() {
		s *= 0.85
	}
	return int(math.Round(math.Max(0, math.Min(100, s))))
}

func severityPoints(f model.Finding) float64 {
	if f.CVSS > 0 {
		return f.CVSS * 6
	}
	switch f.Severity {
	case model.SeverityCritical:
		return 54
	case model.SeverityHigh:
		return 42
	case model.SeverityMedium:
		return 30
	case model.SeverityLow:
		return 15
	default:
		return 10
	}
}

func Apply(findings []model.Finding) {
	for i := range findings {
		findings[i].Score = Compute(findings[i])
	}
}
