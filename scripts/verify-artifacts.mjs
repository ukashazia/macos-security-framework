import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(
    entries.map((entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? sourceFiles(path) : [path];
    }),
  );
  return paths.flat();
}

const sources = [
  ".cargo/config.toml",
  "Cargo.lock",
  "Cargo.toml",
  "build.rs",
  "package.json",
  ...(await sourceFiles("src")),
];
const artifacts = [
  "index.js",
  "index.d.ts",
  "msf_ffi.darwin-arm64.node",
  "msf_ffi.darwin-x64.node",
];
const newestSource = Math.max(
  ...(await Promise.all(sources.map(async (path) => (await stat(path)).mtimeMs))),
);
const failures = [];

for (const path of artifacts) {
  try {
    const metadata = await stat(path);
    if (metadata.size === 0) failures.push(`${path} is empty`);
    if (metadata.mtimeMs < newestSource) failures.push(`${path} is stale`);
  } catch {
    failures.push(`${path} is missing`);
  }
}

if (failures.length > 0) {
  throw new Error(`release artifacts are incomplete:\n- ${failures.join("\n- ")}`);
}
