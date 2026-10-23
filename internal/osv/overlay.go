package osv

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ciloops/vuln-check/internal/model"
)

// Language ecosystems OSV resolves reliably. OS package types are excluded:
// grype already applies distro backport semantics and OSV would reintroduce
// false positives there.
var languagePurlTypes = map[string]bool{
	"npm": true, "pypi": true, "golang": true, "maven": true, "cargo": true,
	"gem": true, "composer": true, "nuget": true, "hex": true, "pub": true,
	"swift": true, "hackage": true, "cran": true,
}

func IsLanguagePackage(p model.Package) bool {
	return p.PURL != "" && languagePurlTypes[purlType(p.PURL)]
}

// Overlay queries OSV for the inventory and returns findings not already
// identified by grype. known holds every id and alias grype reported.
func Overlay(ctx context.Context, c *Client, inventory []model.Package, known map[string]bool) ([]model.Finding, error) {
	var pkgs []model.Package
	var purls []string
	for _, p := range inventory {
		if IsLanguagePackage(p) {
			pkgs = append(pkgs, p)
			purls = append(purls, p.PURL)
		}
	}
	if len(purls) == 0 {
		return nil, nil
	}
	hits, err := c.QueryBatch(ctx, purls)
	if err != nil {
		return nil, err
	}

	type pending struct {
		id   string
		pkgs []model.Package
	}
	byID := map[string]*pending{}
	for i, ids := range hits {
		for _, id := range ids {
			if known[id] {
				continue
			}
			p, ok := byID[id]
			if !ok {
				p = &pending{id: id}
				byID[id] = p
			}
			p.pkgs = append(p.pkgs, pkgs[i])
		}
	}
	if len(byID) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	vulns, err := c.fetchAll(ctx, ids)
	if err != nil {
		return nil, err
	}

	var out []model.Finding
	for _, id := range ids {
		v := vulns[id]
		if v == nil || v.Withdrawn != "" || anyKnown(v.Aliases, known) {
			continue
		}
		for _, p := range byID[id].pkgs {
			out = append(out, toFinding(v, p))
		}
	}
	return out, nil
}

func (c *Client) fetchAll(ctx context.Context, ids []string) (map[string]*Vuln, error) {
	n := c.Concurrency
	if n <= 0 {
		n = 4
	}
	sem := make(chan struct{}, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := map[string]*Vuln{}
	var firstErr error
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			v, err := c.Vuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[id] = v
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, fmt.Errorf("osv detail: %w", firstErr)
	}
	return out, nil
}

func toFinding(v *Vuln, p model.Package) model.Finding {
	f := model.Finding{
		ID:          v.ID,
		Aliases:     append([]string(nil), v.Aliases...),
		Package:     p,
		Description: firstNonEmpty(v.Summary, v.Details),
		Sources:     []string{model.SourceOSV},
		Fresh:       true,
		FixState:    model.FixStateUnknown,
	}
	for _, s := range v.Severity {
		if strings.EqualFold(s.Type, "CVSS_V3") {
			if score := BaseScoreV3(s.Score); score > 0 {
				f.CVSS, f.CVSSVector = score, s.Score
				break
			}
		}
	}
	if label, ok := v.DatabaseSpecific["severity"].(string); ok {
		f.Severity = model.ParseSeverity(label)
	}
	if f.Severity == model.SeverityUnknown || f.Severity == "" {
		f.Severity = model.ParseSeverity(SeverityFromScore(f.CVSS))
	}
	f.FixVersions = fixVersions(v, p)
	if len(f.FixVersions) > 0 {
		f.FixState = model.FixStateFixed
	}
	for _, r := range v.References {
		if len(f.URLs) >= 5 {
			break
		}
		f.URLs = append(f.URLs, r.URL)
	}
	return f
}

func fixVersions(v *Vuln, p model.Package) []string {
	var out []string
	for _, a := range v.Affected {
		if !affectsPackage(a.Package, p) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if fv := e["fixed"]; fv != "" && !contains(out, fv) {
					out = append(out, fv)
				}
			}
		}
	}
	return out
}

func affectsPackage(ap AffectedPackage, p model.Package) bool {
	if ap.Purl != "" && p.PURL != "" {
		if stripVersion(ap.Purl) == stripVersion(p.PURL) {
			return true
		}
	}
	return normalizeName(ap.Name) == normalizeName(p.Name)
}

func anyKnown(ids []string, known map[string]bool) bool {
	for _, id := range ids {
		if known[id] {
			return true
		}
	}
	return false
}

func stripVersion(purl string) string {
	if i := strings.LastIndex(purl, "@"); i > 0 {
		return purl[:i]
	}
	return purl
}

func normalizeName(s string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(s))
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

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
