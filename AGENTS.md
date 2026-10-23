# AGENTS.md

Entry point for agents working on this repo.

## What it is

Single Go binary (`cmd/vuln-check`) that shells out to `grype`, overlays OSV, scores, plans upgrades and serves the result as CLI output or an MCP stdio server. No server, no DB of its own.

## Pipeline

```
grype <target> -o json=… -o cyclonedx-json=…   internal/grype   (exec + parse → model.Scan)
OSV querybatch over the CycloneDX inventory      internal/osv     (language purls only, skip known ids/aliases)
score                                            internal/score   (CVSS, EPSS, KEV, fix → 0..100)
plan                                             internal/remediate (min fix version per package, breaking)
report                                           internal/report  (agent | full | sarif)
mcp                                              internal/mcpserver (official go-sdk, stdio)
```

`internal/scan` orchestrates. `internal/version` is the generic version comparator used by remediation.

## Rules

- grype's JSON is the contract: `internal/grype/document.go` mirrors `grype/presenter/models`. When grype changes a field, update there and the fixture.
- OSV never touches OS purls (deb/apk/rpm). grype owns distro backport semantics.
- The agent format is the product. Keep it small; every new field needs a reason an LLM would act on it.
- No network in unit tests. OSV uses `httptest`; grype uses `testdata/fake-grype.sh` and `internal/grype/testdata` fixtures.
- Code, docs and commits in English.

## Commands

```sh
go test ./...            # unit + CLI e2e with fake grype
go vet ./... && gofmt -l .
go build ./cmd/vuln-check
```

Real e2e needs grype installed: `./vuln-check scan --no-osv ./some-project`.

## Distribution surfaces (keep in sync on version bumps)

`.goreleaser.yaml`, `action.yml`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `server.json`, `npm/package.json` (version is injected at release time).
