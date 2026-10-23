# vuln-check

[![ci](https://github.com/ciloops/vuln-check/actions/workflows/ci.yml/badge.svg)](https://github.com/ciloops/vuln-check/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ciloops/vuln-check/graph/badge.svg)](https://codecov.io/gh/ciloops/vuln-check)
[![release](https://img.shields.io/github/v/release/ciloops/vuln-check?sort=semver)](https://github.com/ciloops/vuln-check/releases)
[![go](https://img.shields.io/github/go-mod/go-version/ciloops/vuln-check)](go.mod)
[![license](https://img.shields.io/github/license/ciloops/vuln-check)](LICENSE)

Vulnerability truth for AI agents. Runs [grype](https://github.com/anchore/grype) locally, merges an [OSV](https://osv.dev) freshness overlay, and returns a prioritised answer with concrete upgrade targets instead of a 40 KB JSON dump.

- Any language with a lockfile (npm, PyPI, Go, Maven, Cargo, RubyGems, Composer, NuGet, Hex, Pub, Swift, R, Conan…), OS packages, container images, SBOMs.
- One score per finding: CVSS + EPSS + CISA KEV + fix availability.
- Remediation plan per package: smallest version that closes every finding, `breaking` flag.
- `CLEAN` is ~20 tokens. Nothing runs on a server; nothing leaves your machine except the optional OSV query.

## Install

```sh
# grype is required
brew install grype            # or: curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

go install github.com/ciloops/vuln-check/cmd/vuln-check@latest
# or
brew install ciloops/tap/vuln-check      # macOS cask
# or
npx @ciloops/vuln-check scan .
```

Binaries for Linux/macOS/Windows on the [Releases](https://github.com/ciloops/vuln-check/releases) page. Docker: `ghcr.io/ciloops/vuln-check` (bundles grype).

## CLI

```sh
vuln-check scan .                               # agent format, OSV overlay on
vuln-check scan python:3.12-slim                # image, pulled from the registry
vuln-check scan sbom:bom.cdx.json
vuln-check scan --format sarif --sarif-out out.sarif .
vuln-check scan --fail-above 69 --no-osv .      # CI gate, exit 2 above threshold
vuln-check vuln CVE-2024-3094
vuln-check db update
```

Output (`--format agent`):

```json
{"status":"ACTION_REQUIRED","target":"dir:.","packages":412,"findings":17,"shown":5,"sources":["grype","osv"],
 "actions":[{"package":"pkg:npm/minimist","current":"1.2.5","target":"1.2.6","breaking":false,"fixes":["CVE-2021-44906"],"score":59}],
 "top":[{"id":"CVE-2021-44906","package":"minimist@1.2.5","severity":"CRITICAL","score":59,"epss":0.015,"fixed_in":["1.2.6"]}],
 "unfixable":3}
```

`status`: `CLEAN` | `REVIEW` (all findings < 40) | `ACTION_REQUIRED`. `fresh: true` marks advisories that came from OSV before grype-db ingested them. `unfixable` counts findings with no fix on the current release line.

## MCP

Tools: `scan_dir`, `scan_image`, `scan_sbom`, `vuln_lookup`, `db_update`.

Claude Code:

```sh
claude mcp add vuln-check -- vuln-check mcp
# or the plugin (adds a skill that tells Claude when to scan):
claude plugin marketplace add ciloops/vuln-check && claude plugin install vuln-check
```

Cursor / Windsurf / VS Code (`.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `.vscode/mcp.json`):

```json
{ "mcpServers": { "vuln-check": { "command": "vuln-check", "args": ["mcp"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vuln-check]
command = "vuln-check"
args = ["mcp"]
```

Add `--no-osv` to the args to keep the dependency list off the network.

## GitHub Action

```yaml
- uses: ciloops/vuln-check@v1
  with:
    target: .            # or an image ref
    fail-above: 69
    sarif: vuln.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: vuln.sarif }
```

## Score

`severity` = CVSS base × 6 (label fallback) · `exploit` = EPSS × 30 · KEV: +10, floor 85 · no fix: × 0.85. Clamped to 0–100. See `internal/score`.

## Freshness

grype-db builds daily and grype refreshes it at most every 2 h. The OSV overlay queries `api.osv.dev` with the purls grype inventoried (language ecosystems only) and adds anything grype-db has not seen yet, usually minutes after a GHSA is published. Disable with `--no-osv`.

## Limits

- No lockfile → transitive dependencies are invisible. Same as every scanner.
- Remediation plans assume a linear release line per package; direct vs transitive is not distinguished yet.
- Version comparison is a generic tokenizer, not per-ecosystem parsers. Good enough for "smallest fix above current"; edge cases exist (PEP 440 post-releases, exotic Maven qualifiers).

## Development

```sh
go test ./...
go build ./cmd/vuln-check
```

Tests run against a fake grype (`cmd/vuln-check/testdata/fake-grype.sh`) and fixtures in `internal/grype/testdata`. CI runs a real grype e2e.

Release: tag `vX.Y.Z` → goreleaser publishes binaries, checksums, ghcr image, Homebrew cask for macOS (needs `HOMEBREW_TAP_GITHUB_TOKEN` and the `ciloops/homebrew-tap` repo) and the npm package via trusted publishing (OIDC, no token: configure the GitHub Actions trusted publisher for `@ciloops/vuln-check` on npmjs.com, workflow `release.yml`).

## License

Apache-2.0. grype and syft are Apache-2.0 by Anchore. Vulnerability data: NVD (public domain), GHSA (CC-BY 4.0), OSV (per source), CISA KEV, FIRST EPSS.
