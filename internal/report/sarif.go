package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ciloops/vuln-check/internal/model"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]any    `json:"properties"`
	DefaultConfig    sarifDefaultLevel `json:"defaultConfiguration"`
}

type sarifDefaultLevel struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	Props     map[string]any  `json:"properties"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func BuildSARIF(scan *model.Scan, toolVersion string) []byte {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{
		Name: "vuln-check", Version: toolVersion,
		InformationURI: "https://github.com/ciloops/vuln-check",
	}}}
	seen := map[string]bool{}
	for _, f := range scan.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.ID,
				Name:             f.ID,
				ShortDescription: sarifText{Text: f.ID + " in " + f.Package.Name},
				FullDescription:  sarifText{Text: firstNonEmpty(f.Description, f.ID)},
				HelpURI:          firstURL(f.URLs),
				Properties: map[string]any{
					"security-severity": fmt.Sprintf("%.1f", securitySeverity(f)),
					"tags":              []string{"security", strings.ToLower(string(f.Severity))},
				},
				DefaultConfig: sarifDefaultLevel{Level: level(f.Severity)},
			})
		}
		msg := fmt.Sprintf("%s: %s %s is vulnerable (score %d)", f.ID, f.Package.Name, f.Package.Version, f.Score)
		if len(f.FixVersions) > 0 {
			msg += ", fixed in " + strings.Join(f.FixVersions, ", ")
		}
		r := sarifResult{
			RuleID:  f.ID,
			Level:   level(f.Severity),
			Message: sarifText{Text: msg},
			Props: map[string]any{
				"score": f.Score, "purl": f.Package.PURL, "kev": f.KEV, "epss": f.EPSS, "fresh": f.Fresh,
			},
		}
		for _, loc := range f.Package.Locations {
			r.Locations = append(r.Locations, sarifLocation{Physical: sarifPhysical{Artifact: sarifArtifact{URI: strings.TrimPrefix(loc, "/")}}})
		}
		run.Results = append(run.Results, r)
	}
	if run.Results == nil {
		run.Results = []sarifResult{}
	}
	if run.Tool.Driver.Rules == nil {
		run.Tool.Driver.Rules = []sarifRule{}
	}
	b, _ := json.MarshalIndent(sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{run}}, "", "  ")
	return b
}

func level(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(f model.Finding) float64 {
	if f.CVSS > 0 {
		return f.CVSS
	}
	switch f.Severity {
	case model.SeverityCritical:
		return 9.5
	case model.SeverityHigh:
		return 8
	case model.SeverityMedium:
		return 5.5
	case model.SeverityLow:
		return 2
	default:
		return 0
	}
}

func firstURL(urls []string) string {
	if len(urls) > 0 {
		return urls[0]
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
