import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const profile = process.argv[2] === "debug" ? "debug" : "release";
mkdirSync(join(root, "native"), { recursive: true });
copyFileSync(join(root, "target", profile, "libmsf_ffi.dylib"), join(root, "native", "msf_ffi.node"));
