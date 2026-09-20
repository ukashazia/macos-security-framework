import { readFile } from "node:fs/promises";

import { parse } from "smol-toml";

const [{ version }, cargo] = await Promise.all([
  readFile("package.json", "utf8").then(JSON.parse),
  readFile("Cargo.toml", "utf8").then(parse),
]);
const cargoVersion = cargo.package?.version;

if (cargoVersion !== version) {
  throw new Error(`version mismatch: npm ${version}, Rust ${cargoVersion}`);
}

const tag = process.env.GITHUB_REF_NAME;

if (tag && tag !== `v${version}`) {
  throw new Error(`release tag must be v${version}`);
}
