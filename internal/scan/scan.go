package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ciloops/vuln-check/internal/grype"
	"github.com/ciloops/vuln-check/internal/model"
	"github.com/ciloops/vuln-check/internal/osv"
	"github.com/ciloops/vuln-check/internal/remediate"
	"github.com/ciloops/vuln-check/internal/score"
)

type GrypeRunner interface {
	Scan(ctx context.Context, target string) (*grype.Result, error)
}

type Overlay interface {
	Overlay(ctx context.Context, inventory []model.Package, known map[string]bool) ([]model.Finding, error)
}

type Options struct {
	Target     string
	OSV        bool
	Timeout    time.Duration
	OSVTimeout time.Duration
}

type Scanner struct {
	Grype   GrypeRunner
	Overlay Overlay
}

type Result struct {
	Scan *model.Scan
	Plan []remediate.Action
}

func New(binary string, withOSV bool) *Scanner {
	s := &Scanner{Grype: grype.NewRunner(binary)}
	if withOSV {
		s.Overlay = osvOverlay{client: osv.NewClient()}
	}
	return s
}

func (s *Scanner) Run(ctx context.Context, opts Options) (*Result, error) {
	target := NormalizeTarget(opts.Target)
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	res, err := s.Grype.Scan(ctx, target)
	if err != nil {
		return nil, err
	}
	sc := grype.ToScan(target, res)

	if opts.OSV && s.Overlay != nil {
		s.applyOverlay(ctx, sc, opts.OSVTimeout)
	}
	score.Apply(sc.Findings)
	return &Result{Scan: sc, Plan: remediate.Plan(sc.Findings)}, nil
}

func (s *Scanner) applyOverlay(ctx context.Context, sc *model.Scan, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	octx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	known := map[string]bool{}
	for _, f := range sc.Findings {
		for _, id := range f.IDs() {
			known[id] = true
		}
	}
	extra, err := s.Overlay.Overlay(octx, sc.Inventory, known)
	if err != nil {
		sc.Warnings = append(sc.Warnings, "osv overlay skipped: "+err.Error())
		return
	}
	sc.Sources = append(sc.Sources, model.SourceOSV)
	sc.Findings = append(sc.Findings, extra...)
}

// NormalizeTarget gives grype an explicit scheme. A bare path that exists on
// disk becomes dir: or file:; anything else is passed through (image refs,
// sbom:, registry:, docker:).
func NormalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "dir:."
	}
	for _, p := range []string{"dir:", "file:", "sbom:", "image:", "registry:", "docker:", "podman:", "oci-dir:", "oci-archive:", "docker-archive:", "singularity:"} {
		if strings.HasPrefix(t, p) {
			return t
		}
	}
	if info, err := os.Stat(t); err == nil {
		if info.IsDir() {
			return "dir:" + t
		}
		if strings.HasSuffix(t, ".json") || strings.HasSuffix(t, ".xml") || strings.HasSuffix(t, ".spdx") {
			return "sbom:" + t
		}
		return "file:" + t
	}
	return t
}

type osvOverlay struct {
	client *osv.Client
}

func (o osvOverlay) Overlay(ctx context.Context, inventory []model.Package, known map[string]bool) ([]model.Finding, error) {
	return osv.Overlay(ctx, o.client, inventory, known)
}

func Describe(r *Result) string {
	return fmt.Sprintf("%s: %d packages, %d findings", r.Scan.Target, r.Scan.Packages, len(r.Scan.Findings))
}
