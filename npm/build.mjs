// Assemble the npm packages for a release: the main @hoophq/leash package plus
// one @hoophq/leash-<os>-<cpu> package per platform, each carrying a natively
// cross-compiled binary. The main package selects the right one at install time
// via optionalDependencies + os/cpu (the esbuild/biome pattern — no postinstall,
// no runtime download). leash is pure Go, so cross-compilation is just `go build`
// with GOOS/GOARCH.
//
//   node npm/build.mjs <version>     # -> npm/build/{leash, @hoophq/leash-*}
//
// The release workflow runs this then `npm publish`es each package directory.

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
if (!version) {
  console.error("usage: node npm/build.mjs <version>");
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const outDir = join(here, "build");
const scope = "@hoophq";

// GOOS/GOARCH -> npm os/cpu (Node's naming, which the shim matches at runtime).
const targets = [
  { goos: "darwin", goarch: "amd64", os: "darwin", cpu: "x64" },
  { goos: "darwin", goarch: "arm64", os: "darwin", cpu: "arm64" },
  { goos: "linux", goarch: "amd64", os: "linux", cpu: "x64" },
  { goos: "linux", goarch: "arm64", os: "linux", cpu: "arm64" },
];

rmSync(outDir, { recursive: true, force: true });

const optionalDependencies = {};
for (const t of targets) {
  const name = `${scope}/leash-${t.os}-${t.cpu}`;
  const pkgDir = join(outDir, name);
  const binPath = join(pkgDir, "bin", "leash");
  mkdirSync(dirname(binPath), { recursive: true });

  execFileSync(
    "go",
    ["build", "-trimpath", "-ldflags", `-s -w -X main.version=${version}`, "-o", binPath, "./cmd/leash"],
    { cwd: repoRoot, stdio: "inherit", env: { ...process.env, GOOS: t.goos, GOARCH: t.goarch, CGO_ENABLED: "0" } }
  );
  chmodSync(binPath, 0o755);

  writeFileSync(
    join(pkgDir, "package.json"),
    JSON.stringify(
      {
        name,
        version,
        description: `Prebuilt leash binary for ${t.os}-${t.cpu}`,
        repository: "github:hoophq/leash",
        license: "MIT",
        os: [t.os],
        cpu: [t.cpu],
        files: ["bin"],
      },
      null,
      2
    ) + "\n"
  );
  optionalDependencies[name] = version;
  console.log(`built ${name}`);
}

// Main package: the bin shim + a manifest that pulls in exactly one platform pkg.
const mainDir = join(outDir, "leash");
mkdirSync(join(mainDir, "bin"), { recursive: true });
cpSync(join(here, "bin", "leash.js"), join(mainDir, "bin", "leash.js"));
cpSync(join(here, "README.md"), join(mainDir, "README.md"));
writeFileSync(
  join(mainDir, "package.json"),
  JSON.stringify(
    {
      name: `${scope}/leash`,
      version,
      description: "Guardrails for AI coding agents — blocks catastrophic tool calls before they run",
      repository: "github:hoophq/leash",
      homepage: "https://github.com/hoophq/leash",
      license: "MIT",
      bin: { leash: "bin/leash.js" },
      optionalDependencies,
      files: ["bin"],
    },
    null,
    2
  ) + "\n"
);
console.log(`assembled ${scope}/leash`);
