# msf-ffi

Synchronous JavaScript and TypeScript bindings for Apple’s Security framework, implemented on top of Rust [`security-framework` 3.7.0](https://crates.io/crates/security-framework/3.7.0).

The package covers the crate’s public API across certificates, identities, keys and signatures, keychains and passwords, item search/add/update, trust and trust settings, policies, PKCS#12 and general imports, CMS, Authorization Services, code signing, cryptographic transforms, randomness, and Secure Transport. macOS-only extension traits are folded into the corresponding JavaScript classes.

## Requirements

- macOS 10.15 or newer
- Node.js 20 or newer
- Rust 1.85 or newer and the Xcode Command Line Tools

## Build and use

```sh
npm run build
```

```js
import {
  DigestBuilder,
  DigestType,
  SecRandom,
} from "msf-ffi";

const nonce = new SecRandom().copyBytes(32);
const digest = new DigestBuilder()
  .type(DigestType.sha2)
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

Secure Transport uses a small TCP adapter because Rust’s `Read + Write` generics cannot cross the Node ABI:

```js
import { ClientBuilder } from "msf-ffi";

const tls = new ClientBuilder().connect("example.com", "example.com", 443);
tls.write("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
console.log(tls.read(16 * 1024).toString());
tls.close();
```

Authentication breakpoints are preserved. An interrupted low-level handshake throws `HandshakeError` with a resumable `stream`; an interrupted client-builder handshake throws `ClientHandshakeError` with a resumable `builder`. Both expose the Rust mid-handshake inspection methods.

All calls are synchronous, matching the Rust crate. Run blocking network, authorization-prompt, and keychain-prompt operations in a Worker when they must not block the Node event loop.

## API mapping

JavaScript uses camelCase, while every method also receives a snake_case alias matching the Rust spelling. Module-shaped exports such as `certificate`, `item`, `secure_transport`, and `os.macos.code_signing` make Rust examples mechanically portable. Top-level Rust function aliases such as `set_generic_password`, `update_item`, and `cms_encode_content` are also exported.

Rust constructors are available as static `new()` factories alongside idiomatic JavaScript constructors. Generic streams are adapted to TCP endpoints, Core Foundation containers become typed JavaScript values, and pointer-only details are folded into the safe builders that own them.

Core Foundation values are translated at the boundary:

| Rust value | JavaScript value |
| --- | --- |
| `CFData`, byte slices | `Buffer` |
| `CFString` | `string` |
| `CFDate` | `Date` |
| `CFURL` file URL | filesystem path `string` |
| bitflags | `number` |
| Security framework reference | disposable class instance |
| builder `CFDictionary` | typed JavaScript builder |

Native reference wrappers provide `dispose()` and are also released by a `FinalizationRegistry`. Explicit disposal is recommended for long-running processes.

Errors are thrown as `SecurityFrameworkError`; its `code` property is populated when the OSStatus can be recovered from the native message. Keychain, trust-setting, authorization, and code-signing calls can prompt or fail based on the host process’s signature, entitlements, sandbox, and UI session.

## Development

```sh
npm run build
npm test
```

The native bridge uses the stable Node-API through `napi-rs`; Security operations are delegated to the pinned Rust crate and its Core Foundation dependencies.
