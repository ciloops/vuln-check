package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ciloops/vuln-check/internal/grype"
	"github.com/ciloops/vuln-check/internal/report"
	"github.com/ciloops/vuln-check/internal/scan"
)

type DB interface {
	DBUpdate(ctx context.Context) (string, error)
	DBStatus(ctx context.Context) (string, error)
	VulnLookup(ctx context.Context, id string) (json.RawMessage, error)
}

type Config struct {
	Version     string
	Scanner     *scan.Scanner
	DB          DB
	OSV         bool
	ScanTimeout time.Duration
	Report      report.Options
}

type scanDirArgs struct {
	Path string `json:"path" jsonschema:"directory to scan (project root with lockfiles, or any path)"`
	Top  int    `json:"top,omitempty" jsonschema:"max findings to return, default 10"`
}

type scanImageArgs struct {
	Image string `json:"image" jsonschema:"container image reference, e.g. python:3.12-slim or ghcr.io/org/app@sha256:..."`
	Top   int    `json:"top,omitempty" jsonschema:"max findings to return, default 10"`
}

type scanSBOMArgs struct {
	Path string `json:"path" jsonschema:"path to a CycloneDX or SPDX SBOM file"`
	Top  int    `json:"top,omitempty" jsonschema:"max findings to return, default 10"`
}

type vulnArgs struct {
	ID string `json:"id" jsonschema:"vulnerability id: CVE-..., GHSA-..., etc."`
}

type dbStatusOut struct {
	Status string `json:"status"`
}

func New(cfg Config) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "vuln-check", Version: cfg.Version}, nil)
	run := func(ctx context.Context, target string, top int) (*mcp.CallToolResult, report.Agent, error) {
		res, err := cfg.Scanner.Run(ctx, scan.Options{Target: target, OSV: cfg.OSV, Timeout: cfg.ScanTimeout})
		if err != nil {
			return nil, report.Agent{}, err
		}
		opts := cfg.Report
		if top > 0 {
			opts.Top = top
		}
		return nil, report.BuildAgent(res.Scan, res.Plan, opts), nil
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "scan_dir",
		Description: "Scan a project directory for known vulnerabilities in its dependencies (any language with a lockfile) and OS packages. Returns a prioritized summary with concrete upgrade actions. Call this before changing dependency files.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a scanDirArgs) (*mcp.CallToolResult, report.Agent, error) {
		return run(ctx, "dir:"+a.Path, a.Top)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "scan_image",
		Description: "Scan a container image (pulled from the registry, no Docker daemon needed) for vulnerabilities in OS packages and bundled dependencies. Use it to check a Dockerfile's FROM base image before building.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a scanImageArgs) (*mcp.CallToolResult, report.Agent, error) {
		return run(ctx, a.Image, a.Top)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "scan_sbom",
		Description: "Scan an existing CycloneDX or SPDX SBOM file for vulnerabilities.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a scanSBOMArgs) (*mcp.CallToolResult, report.Agent, error) {
		return run(ctx, "sbom:"+a.Path, a.Top)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "vuln_lookup",
		Description: "Look up a vulnerability by id (CVE, GHSA, ...) in the local database: severity, affected packages and fixes.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a vulnArgs) (*mcp.CallToolResult, any, error) {
		raw, err := cfg.DB.VulnLookup(ctx, a.ID)
		if err != nil {
			return nil, nil, err
		}
		var out any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, nil, fmt.Errorf("parse grype output: %w", err)
		}
		return nil, out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "db_update",
		Description: "Update the local vulnerability database now. Scans already refresh it automatically once a day; call this only when the newest advisories matter.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, dbStatusOut, error) {
		out, err := cfg.DB.DBUpdate(ctx)
		if err != nil {
			return nil, dbStatusOut{}, err
		}
		return nil, dbStatusOut{Status: out}, nil
	})

	return s
}

func NewDefault(version string, grypeBinary string, withOSV bool) *mcp.Server {
	runner := grype.NewRunner(grypeBinary)
	return New(Config{
		Version:     version,
		Scanner:     scan.New(grypeBinary, withOSV),
		DB:          runner,
		OSV:         withOSV,
		ScanTimeout: 10 * time.Minute,
		Report:      report.DefaultOptions(),
	})
}

func Serve(ctx context.Context, s *mcp.Server) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}
