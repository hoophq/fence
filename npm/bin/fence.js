#!/usr/bin/env node
"use strict";

// Resolve the prebuilt fence binary for this platform and exec it.
//
// The matching @hoophq/fence-<os>-<cpu> package is installed by npm as an
// optionalDependency, gated by its own `os`/`cpu` fields — so exactly one lands
// on any given machine. There is no postinstall and no download at runtime: a
// guardrail that flags `curl | sh` and postinstall hooks must not ship as one.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");

function binaryPath() {
  const pkg = `@hoophq/fence-${process.platform}-${process.arch}`;
  try {
    return require.resolve(`${pkg}/bin/fence`);
  } catch {
    return null;
  }
}

const bin = binaryPath();
if (!bin) {
  const windows =
    process.platform === "win32"
      ? `Native Windows isn't supported yet — run Fence inside WSL (works exactly as on Linux),\n` +
        `or follow https://github.com/hoophq/fence/issues/26 for native support.\n`
      : "";
  console.error(
    `fence: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `Supported: darwin/linux on x64/arm64.\n` +
      windows +
      `Install from source instead: go install github.com/hoophq/fence/cmd/fence@latest`
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
  console.error(`fence: ${res.error.message}`);
  process.exit(1);
}
process.exit(res.status === null ? 1 : res.status);
