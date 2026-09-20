import assert from "node:assert/strict";
import test from "node:test";

import {
  __napiBindingTarget,
  DigestBuilder,
  DigestType,
  ItemSearchOptions,
  SecCode,
  SecRandom,
  SslConnectionType,
  SslSessionState,
  SslSide,
  SslContext,
  accessControlFlags,
  cipherSuites,
  securityFrameworkErrorMessage,
} from "../index.js";

test("napi-rs loads the native addon", () => {
  assert.equal(__napiBindingTarget, "native");
  assert.equal(new SecRandom().copyBytes(32).length, 32);
});

test("typed digest bindings accept and return buffers", () => {
  const digest = new DigestBuilder()
    .digestType(DigestType.Sha2)
    .length(256)
    .execute(Buffer.from("abc"));

  assert.equal(
    digest.toString("hex"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("invalid numeric inputs are rejected at the JavaScript boundary", () => {
  assert.throws(
    () => new DigestBuilder().length(0),
    /digest length must be positive/,
  );
  assert.throws(
    () => new ItemSearchOptions().limit(-1),
    /item search limit must be positive/,
  );
  assert.throws(
    () =>
      new SslContext(SslSide.Client, SslConnectionType.Stream).setEnabledCiphers([
        0x1_0000,
      ]),
    /TLS cipher suite must fit in 16 bits/,
  );
});

test("Security.framework errors expose messages", () => {
  assert.match(securityFrameworkErrorMessage(-25300), /not be found/i);
});

test("cipher suites are exported from the Rust binding", () => {
  const suites = cipherSuites();
  assert.ok(Object.keys(suites).length >= 150);
  assert.equal(suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0xc02f);
});

test("Rust bitflags have named JavaScript values", () => {
  const flags = accessControlFlags();
  assert.ok(flags.userPresence > 0);
  assert.ok(flags.privateKeyUsage > 0);
});

test("Secure Transport context is a typed native class", () => {
  const context = new SslContext(SslSide.Client, SslConnectionType.Stream);
  assert.equal(context.state(), SslSessionState.Idle);
  assert.ok(context.supportedCiphers().length > 0);
});

test("code signing wrapper can locate the current executable", () => {
  const code = SecCode.forSelf(0);
  assert.ok(code.path(0).length > 0);
});
