package model

import "strings"

type Severity string

const (
	SeverityCritical   Severity = "CRITICAL"
	SeverityHigh       Severity = "HIGH"
	SeverityMedium     Severity = "MEDIUM"
	SeverityLow        Severity = "LOW"
	SeverityNegligible Severity = "NEGLIGIBLE"
	SeverityUnknown    Severity = "UNKNOWN"
)

func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM", "MODERATE":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	case "NEGLIGIBLE":
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}

const (
	SourceGrype = "grype"
	SourceOSV   = "osv"
)

const (
	FixStateFixed    = "fixed"
	FixStateNotFixed = "not-fixed"
	FixStateWontFix  = "wont-fix"
	FixStateUnknown  = "unknown"
)

type Package struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type"`
	PURL      string   `json:"purl,omitempty"`
	Locations []string `json:"locations,omitempty"`
}

func (p Package) Key() string {
	if p.PURL != "" {
		if i := strings.LastIndex(p.PURL, "@"); i > 0 {
			return p.PURL[:i]
		}
		return p.PURL
	}
	return p.Type + "/" + p.Name
}

type Finding struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases,omitempty"`
	Package        Package  `json:"package"`
	Severity       Severity `json:"severity"`
	CVSS           float64  `json:"cvss,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
	KEV            bool     `json:"kev"`
	FixVersions    []string `json:"fix_versions,omitempty"`
	FixState       string   `json:"fix_state"`
	Description    string   `json:"description,omitempty"`
	URLs           []string `json:"urls,omitempty"`
	Sources        []string `json:"sources"`
	Fresh          bool     `json:"fresh"`
	Score          int      `json:"score"`
}

func (f Finding) IDs() []string {
	out := make([]string, 0, 1+len(f.Aliases))
	out = append(out, f.ID)
	out = append(out, f.Aliases...)
	return out
}

func (f Finding) HasFix() bool {
	return len(f.FixVersions) > 0 && f.FixState != FixStateWontFix
}

type Scan struct {
	Target       string    `json:"target"`
	Packages     int       `json:"packages"`
	Inventory    []Package `json:"-"`
	Findings     []Finding `json:"findings"`
	Sources      []string  `json:"sources"`
	Warnings     []string  `json:"warnings,omitempty"`
	Distro       string    `json:"distro,omitempty"`
	GrypeVersion string    `json:"grype_version,omitempty"`
	DBBuilt      string    `json:"db_built,omitempty"`
}
