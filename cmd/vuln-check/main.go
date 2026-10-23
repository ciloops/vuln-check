package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ciloops/vuln-check/internal/grype"
	"github.com/ciloops/vuln-check/internal/mcpserver"
	"github.com/ciloops/vuln-check/internal/report"
	"github.com/ciloops/vuln-check/internal/scan"
)

var version = "dev"

const usage = `vuln-check — vulnerability truth for AI agents, on top of grype

Usage:
  vuln-check scan [flags] <target>     target: path | dir:path | image ref | sbom:path | registry:ref
  vuln-check mcp [flags]               run the MCP server over stdio
  vuln-check db update|status          manage the local grype database
  vuln-check vuln <id>                 look up a vulnerability id
  vuln-check version

Scan flags:
  --format agent|full|sarif   output format (default agent)
  --top N                     findings to show in agent format (default 10)
  --fail-above N              exit 2 when any finding scores above N (default: never)
  --sarif-out PATH            also write a SARIF report to PATH
  --no-osv                    skip the OSV freshness overlay (no network beyond grype)
  --timeout D                 scan timeout (default 10m)
  --grype PATH                grype binary (default: PATH lookup, or $VULN_CHECK_GRYPE)

Exit codes: 0 ok, 1 error, 2 threshold exceeded
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "mcp":
		err = runMCP(ctx, args[1:])
	case "db":
		err = runDB(ctx, args[1:], stdout)
	case "vuln":
		err = runVuln(ctx, args[1:], stdout)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "agent", "")
	top := fs.Int("top", 10, "")
	failAbove := fs.Int("fail-above", -1, "")
	noOSV := fs.Bool("no-osv", false, "")
	timeout := fs.Duration("timeout", 10*time.Minute, "")
	grypeBin := fs.String("grype", "", "")
	sarifOut := fs.String("sarif-out", "", "")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	sc := scan.New(*grypeBin, !*noOSV)
	res, err := sc.Run(ctx, scan.Options{Target: target, OSV: !*noOSV, Timeout: *timeout})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	opts := report.DefaultOptions()
	opts.Top = *top
	switch *format {
	case "agent":
		stdout.Write(report.BuildAgent(res.Scan, res.Plan, opts).JSON())
		fmt.Fprintln(stdout)
	case "full":
		stdout.Write(report.BuildFull(res.Scan, res.Plan, opts).JSON())
		fmt.Fprintln(stdout)
	case "sarif":
		stdout.Write(report.BuildSARIF(res.Scan, version))
		fmt.Fprintln(stdout)
	default:
		fmt.Fprintf(stderr, "unknown format %q\n", *format)
		return 1
	}
	if *sarifOut != "" {
		if err := os.WriteFile(*sarifOut, report.BuildSARIF(res.Scan, version), 0o644); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	}
	if *failAbove >= 0 {
		for _, f := range res.Scan.Findings {
			if f.Score > *failAbove {
				fmt.Fprintf(stderr, "threshold exceeded: %s scores %d > %d\n", f.ID, f.Score, *failAbove)
				return 2
			}
		}
	}
	return 0
}

func runMCP(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	noOSV := fs.Bool("no-osv", false, "")
	grypeBin := fs.String("grype", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return mcpserver.Serve(ctx, mcpserver.NewDefault(version, *grypeBin, !*noOSV))
}

func runDB(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: vuln-check db update|status")
	}
	r := grype.NewRunner("")
	var out string
	var err error
	switch args[0] {
	case "update":
		out, err = r.DBUpdate(ctx)
	case "status":
		out, err = r.DBStatus(ctx)
	default:
		return fmt.Errorf("unknown db command %q", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, out)
	return nil
}

func runVuln(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: vuln-check vuln <id>")
	}
	raw, err := grype.NewRunner("").VulnLookup(ctx, args[0])
	if err != nil {
		return err
	}
	stdout.Write(raw)
	fmt.Fprintln(stdout)
	return nil
}
