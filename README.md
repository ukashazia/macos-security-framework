# msf-ffi

Synchronous JavaScript and TypeScript bindings for Apple’s Security framework, implemented with Rust [`security-framework` 3.7.0](https://crates.io/crates/security-framework/3.7.0) and [`napi-rs`](https://napi.rs/).

The binding covers certificates, identities, keys and signatures, keychains and passwords, item search/add/update, policies and trust, trust settings, PKCS#12 and general imports, CMS, Authorization Services, code signing, cryptographic transforms, randomness, cipher suites, and Secure Transport. macOS-only extension traits are folded into the corresponding JavaScript classes.

## Installation

- macOS 12 or newer
- Node.js 20 or newer

```sh
npm install msf-ffi
```

The npm package includes native addons for Apple Silicon and Intel Macs, so consumers do not need Rust or Xcode. The correct addon is selected automatically at runtime.

## Build and test

Building from source additionally requires:

- Rust 1.88 or newer
- Xcode Command Line Tools
- [`just`](https://github.com/casey/just) for the convenience recipes

```sh
npm ci --ignore-scripts
just build
just test
just check
```

`napi-rs` generates `index.js`, `index.d.ts`, and the platform `.node` addon. They are build artifacts; the maintained API lives in the domain modules under `src/api`.

## Release

Published tarballs contain native binaries for both Apple Silicon and Intel Macs. Install both Rust targets before producing one:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm ci --ignore-scripts
just build-all
just release-check
just pack
```

`release-check` rejects missing, empty, or stale generated files, then runs Rust formatting and Clippy, strict TypeScript compilation, native tests, and an npm package dry-run. CI runs the same path with Node.js 20 and Rust 1.88, the package's minimum supported versions, and uploads the verified dual-architecture npm tarball as a build artifact.

## Examples

```js
import { DigestBuilder, DigestType, SecRandom } from "msf-ffi";

const nonce = new SecRandom().copyBytes(32);
const digest = new DigestBuilder()
  .digestType(DigestType.Sha2)
  .length(256)
  .execute(nonce);
```

Passwords remain bytes rather than being silently decoded:

```js
import {
  deleteGenericPassword,
  getGenericPassword,
  setGenericPassword,
} from "msf-ffi";

setGenericPassword("com.example.app", "alice", Buffer.from("secret"));
console.log(getGenericPassword("com.example.app", "alice").toString());
deleteGenericPassword("com.example.app", "alice");
```

Secure Transport uses a TCP adapter because Rust’s generic `Read + Write` streams cannot cross Node-API:

```js
import { ClientBuilder } from "msf-ffi";

const result = new ClientBuilder().connect("example.com", "example.com", 443);
if (result.stream) {
  result.stream.write(
    Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"),
  );
  console.log(result.stream.read(16 * 1024).toString());
  result.stream.close();
}
```

Low-level and client-builder handshakes return typed result objects. An authentication breakpoint contains a resumable `MidHandshakeSslStream` or `MidHandshakeClientBuilder`; terminal failures throw a JavaScript error.

All calls are synchronous, matching the Rust crate. Run blocking network, authorization-prompt, and keychain-prompt operations in a Worker when they must not block the Node event loop.

## API mapping

- Rust structs become native JavaScript classes whose lifetimes are managed by Node-API.
- Rust methods and functions are generated as camelCase JavaScript names.
- Builder methods return `this` where the Rust builder is mutable.
- Rust byte slices and `CFData` become `Buffer`.
- Rust enums become generated TypeScript string or numeric enums.
- Core Foundation dates become Unix timestamps in milliseconds.
- Bitflags remain composable numbers; named values are exported by `accessControlFlags()`, `authorizationFlags()`, `cmsSignedAttributes()`, `codeSigningFlags()`, `revocationPolicyFlags()`, and `trustFlags()`.
- Security framework failures become JavaScript exceptions.
- `cipherSuites()` returns the complete name-to-value map for `CipherSuite` constants.

The generated `index.d.ts` is the authoritative API reference for JavaScript and TypeScript consumers.

## Source layout

```text
src/api/
  security.rs          certificates, identities, keys, policies, trust
  keychain.rs          keychains and macOS password operations
  passwords.rs         portable password APIs
  items.rs             item search, add, update, and references
  imports.rs           PKCS#12 and general imports
  cms.rs               CMS encoder and decoder
  transforms.rs        digest and encryption transforms
  secure_transport.rs  TLS contexts, builders, streams, handshake states
  macos.rs              trust settings, code signing, authorization
  cipher_suites.rs     Secure Transport cipher constants
  random.rs            secure randomness
  error.rs             error conversion
```
