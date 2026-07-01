#!/usr/bin/env node
"use strict";

// Resolve the prebuilt leash binary for this platform and exec it.
//
// The matching @hoophq/leash-<os>-<cpu> package is installed by npm as an
// optionalDependency, gated by its own `os`/`cpu` fields — so exactly one lands
// on any given machine. There is no postinstall and no download at runtime: a
// guardrail that flags `curl | sh` and postinstall hooks must not ship as one.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");

function binaryPath() {
  const pkg = `@hoophq/leash-${process.platform}-${process.arch}`;
  try {
    return require.resolve(`${pkg}/bin/leash`);
  } catch {
    return null;
  }
}

const bin = binaryPath();
if (!bin) {
  console.error(
    `leash: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `Supported: darwin/linux on x64/arm64.\n` +
      `Install from source instead: go install github.com/hoophq/leash/cmd/leash@latest`
  );
  process.exit(1);
}

// Be defensive about the executable bit surviving packaging/extraction.
try {
  fs.chmodSync(bin, 0o755);
} catch {
  // read-only store, etc. — spawn will surface any real problem
}

const res = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (res.error) {
  console.error(`leash: ${res.error.message}`);
  process.exit(1);
}
process.exit(res.status === null ? 1 : res.status);
