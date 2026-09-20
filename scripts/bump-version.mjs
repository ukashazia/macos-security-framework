import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";

import { parse, stringify } from "smol-toml";

const requestedVersion = process.argv[2];

if (!requestedVersion || process.argv.length !== 3) {
  throw new Error("usage: node scripts/bump-version.mjs <version>");
}

const cargoPath = "Cargo.toml";
const cargo = parse(await readFile(cargoPath, "utf8"));

if (!cargo.package || typeof cargo.package !== "object") {
  throw new Error("Cargo.toml is missing [package]");
}

execFileSync(
  "npm",
  ["version", requestedVersion, "--no-git-tag-version", "--ignore-scripts"],
  { stdio: "inherit" },
);

const { version } = JSON.parse(await readFile("package.json", "utf8"));
cargo.package.version = version;
await writeFile(cargoPath, stringify(cargo));

execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
  stdio: ["ignore", "ignore", "inherit"],
});
