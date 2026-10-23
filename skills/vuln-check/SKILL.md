---
name: vuln-check
description: Check a project's dependencies, lockfiles, SBOMs and container base images for known vulnerabilities before changing them. Use whenever the task touches package.json, package-lock.json, requirements.txt, poetry.lock, go.mod, Cargo.lock, composer.lock, Gemfile.lock, pom.xml, *.csproj, a Dockerfile FROM line, or when the user asks whether something is vulnerable, outdated or safe to upgrade.
---

# vuln-check

Local scan on top of grype. The MCP tools return a prioritised summary, not a dump.

## When to call

- Before editing a dependency manifest or lockfile: `scan_dir` on the project root.
- Before changing or choosing a `FROM` image: `scan_image` with the exact reference (tag or digest).
- When the user asks "is X vulnerable", "what should I upgrade", "is this image safe": scan, then answer from the result.
- When you already have an SBOM: `scan_sbom`.
- Do not call `db_update` by default; the database refreshes itself daily. Use it only when the user needs the newest advisories.

## Reading the result

- `status`: `CLEAN` means stop, nothing to do. `ACTION_REQUIRED` means at least one finding scored >= 40. `REVIEW` means only low-score findings.
- `actions[]` is the plan: for each package, `target` is the smallest version that closes every fixable finding. `breaking: true` crosses a major boundary; say so before applying. `unfixed[]` lists ids the target does not close.
- `top[]` is ranked by `score` (0-100: CVSS, EPSS, KEV, fix availability). `exploited: true` means CISA KEV, treat as urgent. `fresh: true` means the advisory came from OSV in the last hours and lacks enrichment; still real.
- `unfixable` counts findings with no fix on this release line. Report them, do not invent upgrades.
- `sources` tells which sources answered. If `osv` is missing, the network overlay was skipped and freshness is ~24h.

## Acting on it

1. Apply non-breaking `actions` directly in the manifest/lockfile.
2. For `breaking: true`, show the user the package, current -> target, and the ids it fixes; ask before applying.
3. After editing, re-run the scan to confirm `CLEAN` or that only `unfixable` remain.
4. Never claim a version is safe without a scan result that says so.

## Limits

- No lockfile means transitive dependencies are invisible. Say so if the project lacks one.
- OS packages come from the image or filesystem being scanned, not from the Dockerfile text.
- Results are only as fresh as grype-db (daily) plus the OSV overlay (minutes-hours) for language ecosystems.
