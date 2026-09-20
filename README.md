# macos-security-framework

Synchronous JavaScript and TypeScript bindings for Apple’s Security framework, implemented with Rust [`security-framework` 3.7.0](https://crates.io/crates/security-framework/3.7.0) and [`napi-rs`](https://napi.rs/).

The binding covers certificates, identities, keys and signatures, keychains and passwords, item search/add/update, policies and trust, trust settings, PKCS#12 and general imports, CMS, Authorization Services, code signing, cryptographic transforms, randomness, cipher suites, and Secure Transport. macOS-only extension traits are folded into the corresponding JavaScript classes.

## Installation

- macOS 12 or newer
- Node.js 20 or newer

```sh
npm install macos-security-framework
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

Published tarballs contain native binaries for both Apple Silicon and Intel Macs. To publish a release:

1. Add an npm granular access token with publish permission as the GitHub repository secret `NPM_TOKEN`.
2. Run `just bump patch` (or `minor`, `major`, or an exact version) to update the npm and Rust package versions together.
3. Push the release commit to `main`.
4. Push a tag matching the package version, such as `v0.1.0`.

Regular CI only builds, tests, and checks pushes to `main` and pull requests targeting `main`. A version tag builds both architectures, runs `just release-check`, and creates the GitHub Release with the repository token. The release workflow then calls the publish workflow, which runs `just publish` and publishes the public npm package with provenance.

To publish locally instead, install both Rust targets, run `just build-all`, authenticate with `npm login`, and run `just publish`. Local publishing uses the authenticated npm session and omits GitHub-only provenance; the release gate rejects missing or stale artifacts.

## Examples

```js
import { DigestBuilder, DigestType, SecRandom } from "macos-security-framework";

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
} from "macos-security-framework";

setGenericPassword("com.example.app", "alice", Buffer.from("secret"));
console.log(getGenericPassword("com.example.app", "alice").toString());
deleteGenericPassword("com.example.app", "alice");
```

Secure Transport uses a TCP adapter because Rust’s generic `Read + Write` streams cannot cross Node-API:

```js
import { ClientBuilder } from "macos-security-framework";

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
