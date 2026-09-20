# macos-security-framework

Synchronous JavaScript and TypeScript access to Apple’s Security framework on macOS.

The package covers keychains, passwords, certificates, identities, keys, trust evaluation,
item queries, imports, CMS, cryptographic operations, Authorization Services, code signing,
randomness, cipher suites, and Secure Transport.

## Requirements

- macOS 12 or newer
- Node.js 20 or newer

Apple Silicon and Intel Macs are supported with no local compilation required.

## Installation

```sh
npm install macos-security-framework
```

## Usage

```js
import { DigestBuilder, DigestType, SecRandom } from "macos-security-framework";

const nonce = new SecRandom().copyBytes(32);
const digest = new DigestBuilder()
  .digestType(DigestType.Sha2)
  .length(256)
  .execute(nonce);
```

Password values are returned as `Buffer` instances:

```js
import {
  deleteGenericPassword,
  getGenericPassword,
  setGenericPassword,
} from "macos-security-framework";

setGenericPassword("com.example.app", "alice", Buffer.from("secret"));

const password = getGenericPassword("com.example.app", "alice");
console.log(password.toString());

deleteGenericPassword("com.example.app", "alice");
```

## Public API

- **Keychains and passwords:** `SecKeychain`, `KeychainCreateOptions`, `KeychainSettings`,
  `PasswordOptions`, and generic or internet password operations.
- **Certificates, identities, keys, and trust:** `SecCertificate`, `SecIdentity`, `SecKey`,
  `GenerateKeyOptions`, `SecAccessControl`, `SecPolicy`, and `SecTrust`.
- **Security items:** `ItemSearchOptions`, `ItemAddOptions`, `ItemUpdateOptions`,
  `ItemSearchResult`, and `SecKeychainItem`.
- **Imports and CMS:** `Pkcs12ImportOptions`, `ImportOptions`, `CmsEncoder`, `CmsDecoder`,
  and `cmsEncodeContent`.
- **Cryptography:** `DigestBuilder`, `EncryptBuilder`, `SecRandom`, and the related algorithm,
  mode, and padding enums.
- **Secure Transport:** `SslContext`, `SslStream`, `ClientBuilder`, `ServerBuilder`, and typed
  handshake states and results.
- **Authorization and code signing:** `Authorization`, `SecCode`, `SecStaticCode`,
  `SecRequirement`, and `GuestAttributes`.
- **Trust settings and constants:** `TrustSettings`, flag-value helpers, `cipherSuites`, and
  `securityFrameworkErrorMessage`.

The bundled TypeScript declarations provide the complete signatures, enums, options, and result
objects.

## API behavior

- All operations are synchronous. Use a Worker for calls that may block on network activity or
  system prompts.
- Binary values use `Buffer`.
- Dates use Unix timestamps in milliseconds.
- Methods and functions use camelCase names.
- Mutable builder methods return `this` for chaining.
- Bitflags are composable numbers with exported helpers for named values.
- Security framework failures are raised as JavaScript exceptions.

## Development

```sh
npm ci --ignore-scripts
just test
just check
```

## License

[MIT](LICENSE)
