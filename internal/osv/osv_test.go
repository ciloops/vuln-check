package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ciloops/vuln-check/internal/model"
)

func TestBaseScoreV3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":                    9.8,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H":                    7.2,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N":                    6.1,
		"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N":                    2.2,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N":                    0,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 0,
		"garbage": 0,
	}
	for v, want := range cases {
		if got := BaseScoreV3(v); got != want {
			t.Errorf("%s: got %v want %v", v, got, want)
		}
	}
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		resp := batchResponse{}
		for _, q := range req.Queries {
			var ids []string
			switch {
			case strings.HasPrefix(q.Package.Purl, "pkg:npm/lodash@"):
				ids = []string{"GHSA-35jh-r3h4-6jhm"}
			case strings.HasPrefix(q.Package.Purl, "pkg:npm/express@"):
				ids = []string{"GHSA-fresh-0001"}
			case strings.HasPrefix(q.Package.Purl, "pkg:pypi/requests@"):
				ids = []string{"GHSA-9wx4-h78v-vm56", "GHSA-withdrawn-0002"}
			case strings.HasPrefix(q.Package.Purl, "pkg:deb/"):
				t.Errorf("OS purl must not be queried: %s", q.Package.Purl)
			}
			var entry struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			}
			for _, id := range ids {
				entry.Vulns = append(entry.Vulns, struct {
					ID string `json:"id"`
				}{id})
			}
			resp.Results = append(resp.Results, entry)
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		switch id {
		case "GHSA-fresh-0001":
			json.NewEncoder(w).Encode(Vuln{
				ID: id, Aliases: []string{"CVE-2026-99999"}, Summary: "express path traversal",
				Severity:         []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
				DatabaseSpecific: map[string]any{"severity": "HIGH"},
				Affected: []Affected{{
					Package: AffectedPackage{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
					Ranges:  []Range{{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "4.19.3"}}}},
				}, {
					Package: AffectedPackage{Ecosystem: "npm", Name: "other", Purl: "pkg:npm/other"},
					Ranges:  []Range{{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "9.9.9"}}}},
				}},
				References: []Reference{{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-fresh-0001"}},
			})
		case "GHSA-9wx4-h78v-vm56":
			json.NewEncoder(w).Encode(Vuln{
				ID: id, Aliases: []string{"CVE-2024-35195"}, Summary: "requests verify=False session",
				Severity: []Severity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}},
				Affected: []Affected{{
					Package: AffectedPackage{Ecosystem: "PyPI", Name: "requests"},
					Ranges:  []Range{{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "0"}, {"fixed": "2.32.0"}}}},
				}},
			})
		case "GHSA-withdrawn-0002":
			json.NewEncoder(w).Encode(Vuln{ID: id, Withdrawn: "2025-01-01T00:00:00Z"})
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOverlay(t *testing.T) {
	srv := newServer(t)
	c := NewClient()
	c.BaseURL = srv.URL

	inventory := []model.Package{
		{Name: "lodash", Version: "4.17.20", Type: "npm", PURL: "pkg:npm/lodash@4.17.20"},
		{Name: "express", Version: "4.19.2", Type: "npm", PURL: "pkg:npm/express@4.19.2"},
		{Name: "requests", Version: "2.31.0", Type: "pypi", PURL: "pkg:pypi/requests@2.31.0"},
		{Name: "liblzma5", Version: "5.6.0-0.2", Type: "deb", PURL: "pkg:deb/ubuntu/liblzma5@5.6.0-0.2"},
		{Name: "nopurl", Version: "1", Type: "npm"},
	}
	known := map[string]bool{"CVE-2021-23337": true, "GHSA-35jh-r3h4-6jhm": true}

	got, err := Overlay(context.Background(), c, inventory, known)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d: %+v", len(got), got)
	}
	byID := map[string]model.Finding{}
	for _, f := range got {
		byID[f.ID] = f
	}
	express := byID["GHSA-fresh-0001"]
	if !express.Fresh || express.Severity != model.SeverityHigh || express.CVSS != 7.5 {
		t.Errorf("express = %+v", express)
	}
	if len(express.FixVersions) != 1 || express.FixVersions[0] != "4.19.3" {
		t.Errorf("express fixes must come only from the matching affected entry: %v", express.FixVersions)
	}
	if express.FixState != model.FixStateFixed || express.Aliases[0] != "CVE-2026-99999" || express.Package.PURL != "pkg:npm/express@4.19.2" {
		t.Errorf("express = %+v", express)
	}
	requests := byID["GHSA-9wx4-h78v-vm56"]
	if requests.Severity != model.SeverityUnknown || requests.CVSS != 0 || requests.FixVersions[0] != "2.32.0" {
		t.Errorf("requests (cvss4 only, no label) = %+v", requests)
	}
}

func TestOverlayNoLanguagePackages(t *testing.T) {
	c := NewClient()
	c.BaseURL = "http://127.0.0.1:1"
	got, err := Overlay(context.Background(), c, []model.Package{{PURL: "pkg:deb/x@1"}}, nil)
	if err != nil || got != nil {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestOverlayServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	c := NewClient()
	c.BaseURL = srv.URL
	if _, err := Overlay(context.Background(), c, []model.Package{{PURL: "pkg:npm/a@1"}}, nil); err == nil {
		t.Fatal("expected error")
	}
}
