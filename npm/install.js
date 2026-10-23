#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const REPO = "ciloops/vuln-check";
const pkg = require("./package.json");

const platforms = { linux: "linux", darwin: "darwin", win32: "windows" };
const arches = { x64: "amd64", arm64: "arm64" };

function target() {
  const goos = platforms[process.platform];
  const goarch = arches[process.arch];
  if (!goos || !goarch) {
    throw new Error(`unsupported platform ${process.platform}/${process.arch}; build from source: go install github.com/${REPO}/cmd/vuln-check@latest`);
  }
  return { goos, goarch, ext: goos === "windows" ? "zip" : "tar.gz" };
}

async function download(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed ${res.status}: ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function main() {
  if (pkg.version === "0.0.0") {
    console.log("vuln-check: development package, skipping binary download");
    return;
  }
  const { goos, goarch, ext } = target();
  const base = `https://github.com/${REPO}/releases/download/v${pkg.version}`;
  const archive = `vuln-check_${pkg.version}_${goos}_${goarch}.${ext}`;

  const [data, sums] = await Promise.all([download(`${base}/${archive}`), download(`${base}/checksums.txt`)]);
  const expected = sums
    .toString()
    .split("\n")
    .map((l) => l.trim().split(/\s+/))
    .find((p) => p[1] === archive);
  const actual = crypto.createHash("sha256").update(data).digest("hex");
  if (!expected || expected[0] !== actual) {
    throw new Error(`checksum mismatch for ${archive}`);
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vuln-check-"));
  const archivePath = path.join(tmp, archive);
  fs.writeFileSync(archivePath, data);
  execFileSync("tar", ["-xf", archivePath, "-C", tmp]);

  const binName = goos === "windows" ? "vuln-check.exe" : "vuln-check";
  const dest = path.join(__dirname, "bin", binName);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(path.join(tmp, binName), dest);
  fs.chmodSync(dest, 0o755);
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`vuln-check ${pkg.version} installed (${goos}/${goarch}). Requires grype: https://github.com/anchore/grype#installation`);
}

main().catch((err) => {
  console.error(`vuln-check install: ${err.message}`);
  process.exit(1);
});
