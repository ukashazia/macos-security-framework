import assert from "node:assert/strict";
import test from "node:test";

import * as sf from "../index.js";

test("native addon and byte conversion work", () => {
  assert.equal(new sf.SecRandom().copyBytes(32).length, 32);
  assert.equal(
    new sf.DigestBuilder().type(sf.DigestType.sha2).length(256).execute("abc").toString("hex"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("Security.framework errors expose messages", () => {
  assert.match(sf.SecurityFrameworkError.message(-25300), /not be found/i);
});

test("Rust API families and exact-name aliases are exported", () => {
  for (const name of [
    "access_control", "authorization", "base", "certificate", "cipher_suite", "cms",
    "identity", "import_export", "item", "key", "os", "passwords", "policy", "random",
    "secure_transport", "trust", "trust_settings",
  ]) assert.ok(sf[name], name);

  assert.equal(sf.SecCertificate.from_der, sf.SecCertificate.fromDer);
  assert.equal(sf.SecTrust.create_with_certificates, sf.SecTrust.createWithCertificates);
  assert.equal(sf.set_generic_password, sf.setGenericPassword);
  assert.equal(sf.add_item, sf.addItem);
  assert.equal(sf.DigestBuilder.prototype.type_, sf.DigestBuilder.prototype.type);
  assert.equal(sf.PasswordOptions.new_generic_password, sf.PasswordOptions.newGenericPassword);
  assert.equal(sf.ItemAddOptions.prototype.set_account_name, sf.ItemAddOptions.prototype.setAccountName);
  assert.equal(sf.ItemSearchOptions.prototype.pub_key_hash, sf.ItemSearchOptions.prototype.publicKeyHash);
  assert.equal(sf.RevocationPolicy.USE_ANY_METHOD_AVAILABLE, sf.RevocationPolicy.useAnyMethodAvailable);
  assert.equal(sf.TrustSettingsDomain.User, sf.TrustSettingsDomain.user);
  assert.equal(sf.item.Limit, sf.Limit);
  assert.equal(sf.secure_transport.MidHandshakeSslStream, sf.MidHandshakeSslStream);
  assert.equal(sf.secure_transport.MidHandshakeClientBuilder, sf.MidHandshakeClientBuilder);
  assert.equal(sf.CMSDecoder, sf.CmsDecoder);
  assert.ok(Object.keys(sf.Algorithm).length >= 75);
  assert.ok(Object.keys(sf.CipherSuite).length >= 150);
});

test("code signing wrapper can locate the current executable", () => {
  const code = sf.SecCode.forSelf();
  assert.ok(code.path().length > 0);
  code.dispose();
});
