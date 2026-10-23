package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ciloops/vuln-check/internal/grype"
	"github.com/ciloops/vuln-check/internal/report"
	"github.com/ciloops/vuln-check/internal/scan"
)

type fakeGrype struct{ targets []string }

func (f *fakeGrype) Scan(_ context.Context, target string) (*grype.Result, error) {
	f.targets = append(f.targets, target)
	res := &grype.Result{}
	for name, dst := range map[string]any{"grype.json": &res.Document, "sbom.cdx.json": &res.Inventory} {
		b, err := os.ReadFile(filepath.Join("..", "grype", "testdata", name))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return nil, err
		}
	}
	return res, nil
}

type fakeDB struct{}

func (fakeDB) DBUpdate(context.Context) (string, error) { return "updated", nil }
func (fakeDB) DBStatus(context.Context) (string, error) { return "ok", nil }
func (fakeDB) VulnLookup(_ context.Context, id string) (json.RawMessage, error) {
	if id == "CVE-0" {
		return nil, errors.New("not found")
	}
	return json.RawMessage(`[{"id":"` + id + `","severity":"high"}]`), nil
}

func newSession(t *testing.T) (*mcp.ClientSession, *fakeGrype) {
	t.Helper()
	g := &fakeGrype{}
	srv := New(Config{
		Version: "test",
		Scanner: &scan.Scanner{Grype: g},
		DB:      fakeDB{},
		Report:  report.DefaultOptions(),
	})
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, g
}

func TestToolsListed(t *testing.T) {
	cs, _ := newSession(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{"scan_dir", "scan_image", "scan_sbom", "vuln_lookup", "db_update"} {
		if !got[want] {
			t.Errorf("missing tool %s (have %v)", want, got)
		}
	}
}

func TestScanDirReturnsAgentReport(t *testing.T) {
	cs, g := newSession(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "scan_dir", Arguments: map[string]any{"path": "/work/app", "top": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	if g.targets[0] != "dir:/work/app" {
		t.Errorf("target = %q", g.targets[0])
	}
	b, _ := json.Marshal(res.StructuredContent)
	var a report.Agent
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if a.Status != report.StatusActionRequired || a.Shown != 2 || a.Packages != 6 {
		t.Errorf("agent = %+v", a)
	}
	if len(res.Content) == 0 {
		t.Error("text content must be populated for clients without structured output")
	}
}

func TestVulnLookupAndErrors(t *testing.T) {
	cs, _ := newSession(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "vuln_lookup", Arguments: map[string]any{"id": "CVE-2021-23337"}})
	if err != nil || res.IsError {
		t.Fatalf("lookup: %v %+v", err, res)
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "vuln_lookup", Arguments: map[string]any{"id": "CVE-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected tool error for unknown id")
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "db_update", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("db_update: %v %+v", err, res)
	}
}
