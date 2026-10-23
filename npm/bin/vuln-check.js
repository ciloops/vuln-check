#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const bin = path.join(__dirname, process.platform === "win32" ? "vuln-check.exe" : "vuln-check");

if (!fs.existsSync(bin)) {
  const install = spawnSync(process.execPath, [path.join(__dirname, "..", "install.js")], { stdio: "inherit" });
  if (install.status !== 0 || !fs.existsSync(bin)) {
    process.exit(install.status || 1);
  }
}

const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
