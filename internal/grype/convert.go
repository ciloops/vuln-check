package grype

import (
	"strings"

	"github.com/ciloops/vuln-check/internal/model"
)

func ToScan(target string, res *Result) *model.Scan {
	doc := &res.Document
	scan := &model.Scan{
		Target:       target,
		Sources:      []string{model.SourceGrype},
		GrypeVersion: res.Version,
		DBBuilt:      dbBuilt(doc.Descriptor.DB),
	}
	if doc.Distro.Name != "" {
		scan.Distro = strings.TrimSpace(doc.Distro.Name + " " + doc.Distro.Version)
	}
	scan.Inventory = inventory(res)
	scan.Packages = len(scan.Inventory)

	seen := map[string]bool{}
	for _, m := range doc.Matches {
		f := toFinding(m)
		key := f.ID + "|" + f.Package.Key() + "@" + f.Package.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		scan.Findings = append(scan.Findings, f)
	}
	return scan
}

func toFinding(m Match) model.Finding {
	v := m.Vulnerability
	f := model.Finding{
		ID:          v.ID,
		Package:     toPackage(m.Artifact),
		Severity:    model.ParseSeverity(v.Severity),
		Description: v.Description,
		URLs:        v.URLs,
		FixVersions: append([]string(nil), v.Fix.Versions...),
		FixState:    fixState(v.Fix.State),
		Sources:     []string{model.SourceGrype},
		KEV:         len(v.KnownExploited) > 0,
	}
	for _, r := range m.RelatedVulnerabilities {
		if r.ID != "" && r.ID != v.ID {
			f.Aliases = append(f.Aliases, r.ID)
		}
		if f.Severity == model.SeverityUnknown {
			f.Severity = model.ParseSeverity(r.Severity)
		}
		if f.Description == "" {
			f.Description = r.Description
		}
	}
	f.CVSS, f.CVSSVector = pickCVSS(v.Cvss)
	if f.CVSS == 0 {
		for _, r := range m.RelatedVulnerabilities {
			if f.CVSS, f.CVSSVector = pickCVSS(r.Cvss); f.CVSS > 0 {
				break
			}
		}
	}
	if len(v.EPSS) > 0 {
		f.EPSS, f.EPSSPercentile = v.EPSS[0].EPSS, v.EPSS[0].Percentile
	}
	for _, d := range m.MatchDetails {
		if d.Fix != nil && d.Fix.SuggestedVersion != "" && !contains(f.FixVersions, d.Fix.SuggestedVersion) {
			f.FixVersions = append(f.FixVersions, d.Fix.SuggestedVersion)
		}
	}
	if len(f.FixVersions) > 0 && f.FixState == model.FixStateUnknown {
		f.FixState = model.FixStateFixed
	}
	return f
}

func toPackage(a Artifact) model.Package {
	p := model.Package{Name: a.Name, Version: a.Version, Type: a.Type, PURL: a.PURL}
	for _, l := range a.Locations {
		if l.Path != "" && !contains(p.Locations, l.Path) {
			p.Locations = append(p.Locations, l.Path)
		}
	}
	return p
}

func inventory(res *Result) []model.Package {
	var out []model.Package
	seen := map[string]bool{}
	for _, c := range res.Inventory.Components {
		if c.Type != "library" && c.Type != "application" && c.Type != "" {
			continue
		}
		key := c.PURL
		if key == "" {
			key = c.Name + "@" + c.Version
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.Package{Name: c.Name, Version: c.Version, Type: purlType(c.PURL), PURL: c.PURL})
	}
	if len(out) == 0 {
		for _, m := range res.Document.Matches {
			p := toPackage(m.Artifact)
			key := p.Key() + "@" + p.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

func pickCVSS(list []Cvss) (float64, string) {
	best := -1
	for i, c := range list {
		if c.Metrics.BaseScore == 0 {
			continue
		}
		if best < 0 || rank(c) > rank(list[best]) {
			best = i
		}
	}
	if best < 0 {
		return 0, ""
	}
	return list[best].Metrics.BaseScore, list[best].Vector
}

func rank(c Cvss) int {
	r := 0
	if strings.EqualFold(c.Type, "Primary") {
		r += 100
	}
	switch {
	case strings.HasPrefix(c.Version, "4"):
		r += 30
	case strings.HasPrefix(c.Version, "3"):
		r += 40
	case strings.HasPrefix(c.Version, "2"):
		r += 10
	}
	return r
}

func fixState(s string) string {
	switch strings.ToLower(s) {
	case "fixed":
		return model.FixStateFixed
	case "not-fixed":
		return model.FixStateNotFixed
	case "wont-fix":
		return model.FixStateWontFix
	default:
		return model.FixStateUnknown
	}
}

func dbBuilt(db any) string {
	m, ok := db.(map[string]any)
	if !ok {
		return ""
	}
	if s, ok := m["built"].(string); ok {
		return s
	}
	return ""
}

func purlType(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[4:]
	if i := strings.Index(rest, "/"); i > 0 {
		return rest[:i]
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
