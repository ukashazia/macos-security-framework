import { createRequire } from "node:module";
import { CipherSuites } from "./cipher-suites.js";

if (process.platform !== "darwin") {
  throw new Error("msf-ffi only supports macOS");
}

const { invoke: nativeInvoke } = createRequire(import.meta.url)("./native/msf_ffi.node");

export class SecurityFrameworkError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "SecurityFrameworkError";
    const match = message.match(/(?:OSStatus error\s+|\()(-?\d+)/);
    this.code = code ?? (match ? Number(match[1]) : undefined);
  }

  static message(code) {
    return call("error.message", { code });
  }

  static fromCode(code) {
    return new this(this.message(code) ?? `OSStatus ${code}`, code);
  }
}

export class HandshakeError extends SecurityFrameworkError {
  constructor(message, stream = null) {
    super(message);
    this.name = "HandshakeError";
    this.kind = stream == null ? "failure" : "interrupted";
    this.stream = stream;
  }
}

export class ClientHandshakeError extends SecurityFrameworkError {
  constructor(message, builder = null) {
    super(message);
    this.name = "ClientHandshakeError";
    this.kind = builder == null ? "failure" : "interrupted";
    this.builder = builder;
  }
}

function call(operation, args = {}) {
  const response = JSON.parse(nativeInvoke(JSON.stringify({ operation, args })));
  if (!response.ok) throw new SecurityFrameworkError(response.error.message);
  return response.value;
}

function toHex(value) {
  if (typeof value === "string") return Buffer.from(value).toString("hex");
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex");
  if (value instanceof ArrayBuffer) return Buffer.from(value).toString("hex");
  throw new TypeError("expected a string, ArrayBuffer, Buffer, or typed array");
}

const fromHex = (value) => value == null ? null : Buffer.from(value, "hex");
const ids = (values) => values.map((value) => value.handle);
const finalizer = new FinalizationRegistry((handle) => {
  try { call("release", { handle }); } catch { /* process teardown */ }
});

class NativeHandle {
  constructor(handle) {
    if (!Number.isSafeInteger(handle) || handle <= 0) throw new TypeError("invalid native handle");
    this.handle = handle;
    finalizer.register(this, handle, this);
  }

  dispose() {
    if (this.handle !== 0) {
      finalizer.unregister(this);
      call("release", { handle: this.handle });
      this.handle = 0;
    }
  }

  _takeHandle() {
    if (this.handle === 0) throw new TypeError("native handle has already been consumed or disposed");
    finalizer.unregister(this);
    const handle = this.handle;
    this.handle = 0;
    return handle;
  }

  [Symbol.dispose]() { this.dispose(); }
}

export const ProtectionMode = Object.freeze({
  accessibleWhenPasscodeSetThisDeviceOnly: "accessibleWhenPasscodeSetThisDeviceOnly",
  accessibleWhenUnlockedThisDeviceOnly: "accessibleWhenUnlockedThisDeviceOnly",
  accessibleWhenUnlocked: "accessibleWhenUnlocked",
  accessibleAfterFirstUnlockThisDeviceOnly: "accessibleAfterFirstUnlockThisDeviceOnly",
  accessibleAfterFirstUnlock: "accessibleAfterFirstUnlock",
  AccessibleWhenPasscodeSetThisDeviceOnly: "accessibleWhenPasscodeSetThisDeviceOnly",
  AccessibleWhenUnlockedThisDeviceOnly: "accessibleWhenUnlockedThisDeviceOnly",
  AccessibleWhenUnlocked: "accessibleWhenUnlocked",
  AccessibleAfterFirstUnlockThisDeviceOnly: "accessibleAfterFirstUnlockThisDeviceOnly",
  AccessibleAfterFirstUnlock: "accessibleAfterFirstUnlock",
});

export const AccessControlOptions = Object.freeze({
  userPresence: 1 << 0,
  biometryAny: 1 << 1,
  biometryCurrentSet: 1 << 3,
  devicePasscode: 1 << 4,
  watch: 1 << 5,
  companion: 1 << 5,
  or: 1 << 14,
  and: 1 << 15,
  privateKeyUsage: 1 << 30,
  applicationPassword: 1 << 31,
  USER_PRESENCE: 1 << 0, BIOMETRY_ANY: 1 << 1, BIOMETRY_CURRENT_SET: 1 << 3,
  DEVICE_PASSCODE: 1 << 4, WATCH: 1 << 5, COMPANION: 1 << 5, OR: 1 << 14,
  AND: 1 << 15, PRIVATE_KEY_USAGE: 1 << 30, APPLICATION_PASSWORD: 1 << 31,
});

export class SecAccessControl extends NativeHandle {
  static createWithFlags(flags) { return this.createWithProtection(null, flags); }
  static createWithProtection(protection, flags = 0) {
    return new this(call("accessControl.create", { protection, flags }));
  }
}

export class SecCertificate extends NativeHandle {
  static fromDer(data) { return new this(call("certificate.fromDer", { data: toHex(data) })); }
  toDer() { return fromHex(call("certificate.toDer", { handle: this.handle })); }
  addToKeychain(keychain = null) { call("certificate.addToKeychain", { handle: this.handle, keychain: keychain?.handle }); }
  subjectSummary() { return call("certificate.subjectSummary", { handle: this.handle }); }
  emailAddresses() { return call("certificate.emailAddresses", { handle: this.handle }); }
  issuer() { return fromHex(call("certificate.issuer", { handle: this.handle })); }
  subject() { return fromHex(call("certificate.subject", { handle: this.handle })); }
  serialNumberBytes() { return fromHex(call("certificate.serialNumberBytes", { handle: this.handle })); }
  publicKeyInfoDer() { return fromHex(call("certificate.publicKeyInfoDer", { handle: this.handle })); }
  publicKey() { return new SecKey(call("certificate.publicKey", { handle: this.handle })); }
  commonName() { return call("certificate.commonName", { handle: this.handle }); }
  fingerprint() { return fromHex(call("certificate.fingerprint", { handle: this.handle })); }
  signatureAlgorithmProperty() { return call("certificate.signatureAlgorithmProperty", { handle: this.handle }); }
  properties(keys = null) {
    const values = {};
    if (keys == null || keys.includes(CertificateOid.x509V1SignatureAlgorithm)) values[CertificateOid.x509V1SignatureAlgorithm] = this.signatureAlgorithmProperty();
    return new CertificateProperties(values);
  }
  delete() { call("certificate.delete", { handle: this.handle }); }
}
export const CertificateOid = Object.freeze({ x509V1SignatureAlgorithm: "x509V1SignatureAlgorithm", x509_v1_signature_algorithm: "x509V1SignatureAlgorithm" });
export class CertificateProperties {
  constructor(values) { this.values = values; }
  get(oid) { return this.values[oid] ?? null; }
}

export class SecIdentity extends NativeHandle {
  static withCertificate(keychains, certificate) {
    return new this(call("identity.withCertificate", { keychains: ids(keychains), certificate: certificate.handle }));
  }
  certificate() { return new SecCertificate(call("identity.certificate", { handle: this.handle })); }
  privateKey() { return new SecKey(call("identity.privateKey", { handle: this.handle })); }
  delete() { call("identity.delete", { handle: this.handle }); }
}

export const KeyType = Object.freeze({
  rsa: "rsa", dsa: "dsa", aes: "aes", des: "des", tripleDes: "tripleDes",
  rc4: "rc4", cast: "cast", ec: "ec", ecSecPrimeRandom: "ecSecPrimeRandom",
  triple_des: "tripleDes", ec_sec_prime_random: "ecSecPrimeRandom",
});
export const Token = Object.freeze({ software: "software", secureEnclave: "secureEnclave", Software: "software", SecureEnclave: "secureEnclave" });
export const Location = Object.freeze({ defaultFileKeychain: "defaultFileKeychain", dataProtectionKeychain: "dataProtectionKeychain", DefaultFileKeychain: "defaultFileKeychain", DataProtectionKeychain: "dataProtectionKeychain" });
export const fileKeychainLocation = (keychain) => ({ fileKeychain: keychain.handle });

const algorithmNames = [
  "ECIESEncryptionStandardX963SHA1AESGCM", "ECIESEncryptionStandardX963SHA224AESGCM", "ECIESEncryptionStandardX963SHA256AESGCM", "ECIESEncryptionStandardX963SHA384AESGCM", "ECIESEncryptionStandardX963SHA512AESGCM",
  "ECIESEncryptionStandardVariableIVX963SHA224AESGCM", "ECIESEncryptionStandardVariableIVX963SHA256AESGCM", "ECIESEncryptionStandardVariableIVX963SHA384AESGCM", "ECIESEncryptionStandardVariableIVX963SHA512AESGCM",
  "ECIESEncryptionCofactorVariableIVX963SHA224AESGCM", "ECIESEncryptionCofactorVariableIVX963SHA256AESGCM", "ECIESEncryptionCofactorVariableIVX963SHA384AESGCM", "ECIESEncryptionCofactorVariableIVX963SHA512AESGCM",
  "ECIESEncryptionCofactorX963SHA1AESGCM", "ECIESEncryptionCofactorX963SHA224AESGCM", "ECIESEncryptionCofactorX963SHA256AESGCM", "ECIESEncryptionCofactorX963SHA384AESGCM", "ECIESEncryptionCofactorX963SHA512AESGCM",
  "ECDSASignatureRFC4754", "ECDSASignatureDigestX962", "ECDSASignatureDigestX962SHA1", "ECDSASignatureDigestX962SHA224", "ECDSASignatureDigestX962SHA256", "ECDSASignatureDigestX962SHA384", "ECDSASignatureDigestX962SHA512",
  "ECDSASignatureMessageX962SHA1", "ECDSASignatureMessageX962SHA224", "ECDSASignatureMessageX962SHA256", "ECDSASignatureMessageX962SHA384", "ECDSASignatureMessageX962SHA512",
  "ECDHKeyExchangeCofactor", "ECDHKeyExchangeStandard", "ECDHKeyExchangeCofactorX963SHA1", "ECDHKeyExchangeStandardX963SHA1", "ECDHKeyExchangeCofactorX963SHA224", "ECDHKeyExchangeCofactorX963SHA256", "ECDHKeyExchangeCofactorX963SHA384", "ECDHKeyExchangeCofactorX963SHA512", "ECDHKeyExchangeStandardX963SHA224", "ECDHKeyExchangeStandardX963SHA256", "ECDHKeyExchangeStandardX963SHA384", "ECDHKeyExchangeStandardX963SHA512",
  "RSAEncryptionRaw", "RSAEncryptionPKCS1", "RSAEncryptionOAEPSHA1", "RSAEncryptionOAEPSHA224", "RSAEncryptionOAEPSHA256", "RSAEncryptionOAEPSHA384", "RSAEncryptionOAEPSHA512", "RSAEncryptionOAEPSHA1AESGCM", "RSAEncryptionOAEPSHA224AESGCM", "RSAEncryptionOAEPSHA256AESGCM", "RSAEncryptionOAEPSHA384AESGCM", "RSAEncryptionOAEPSHA512AESGCM",
  "RSASignatureRaw", "RSASignatureDigestPKCS1v15Raw", "RSASignatureDigestPKCS1v15SHA1", "RSASignatureDigestPKCS1v15SHA224", "RSASignatureDigestPKCS1v15SHA256", "RSASignatureDigestPKCS1v15SHA384", "RSASignatureDigestPKCS1v15SHA512", "RSASignatureMessagePKCS1v15SHA1", "RSASignatureMessagePKCS1v15SHA224", "RSASignatureMessagePKCS1v15SHA256", "RSASignatureMessagePKCS1v15SHA384", "RSASignatureMessagePKCS1v15SHA512", "RSASignatureDigestPSSSHA1", "RSASignatureDigestPSSSHA224", "RSASignatureDigestPSSSHA256", "RSASignatureDigestPSSSHA384", "RSASignatureDigestPSSSHA512", "RSASignatureMessagePSSSHA1", "RSASignatureMessagePSSSHA224", "RSASignatureMessagePSSSHA256", "RSASignatureMessagePSSSHA384", "RSASignatureMessagePSSSHA512",
];
export const Algorithm = Object.freeze(Object.fromEntries(algorithmNames.map((name) => [name, name])));

export class GenerateKeyOptions {
  constructor() { this.value = {}; }
  setKeyType(value) { this.value.keyType = value; return this; }
  setSizeInBits(value) { this.value.sizeInBits = value; return this; }
  setLabel(value) { this.value.label = value; return this; }
  setToken(value) { this.value.token = value; return this; }
  setLocation(value) { this.value.location = value; return this; }
  setAccessControl(value) { this.value.accessControl = value.handle; return this; }
  setSynchronizable(value) { this.value.synchronizable = value; return this; }
  toDictionary() { return { ...this.value }; }
}

export class SecKey extends NativeHandle {
  static generate(options = new GenerateKeyOptions()) { return new this(call("key.generate", { options: options.value })); }
  static fromData(keyType, data) { return new this(call("key.fromData", { keyType, data: toHex(data) })); }
  applicationLabel() { return fromHex(call("key.applicationLabel", { handle: this.handle })); }
  attributes() { return call("key.attributes", { handle: this.handle }); }
  externalRepresentation() { return fromHex(call("key.externalRepresentation", { handle: this.handle })); }
  publicKey() { const value = call("key.publicKey", { handle: this.handle }); return value == null ? null : new SecKey(value); }
  encryptData(algorithm, data) { return fromHex(call("key.encrypt", { handle: this.handle, algorithm, data: toHex(data) })); }
  decryptData(algorithm, data) { return fromHex(call("key.decrypt", { handle: this.handle, algorithm, data: toHex(data) })); }
  createSignature(algorithm, data) { return fromHex(call("key.sign", { handle: this.handle, algorithm, data: toHex(data) })); }
  verifySignature(algorithm, data, signature) { return call("key.verify", { handle: this.handle, algorithm, data: toHex(data), signature: toHex(signature) }); }
  keyExchange(algorithm, publicKey, requestedSize, sharedInfo = null) { return fromHex(call("key.exchange", { handle: this.handle, algorithm, publicKey: publicKey.handle, requestedSize, sharedInfo: sharedInfo == null ? null : toHex(sharedInfo) })); }
  delete() { call("key.delete", { handle: this.handle }); }
}

export const RevocationPolicy = Object.freeze({ ocsp: 1, crl: 2, preferCrl: 4, requirePositiveResponse: 8, networkAccessDisabled: 16, useAnyMethodAvailable: 3, OCSP_METHOD: 1, CRL_METHOD: 2, PREFER_CRL: 4, REQUIRE_POSITIVE_RESPONSE: 8, NETWORK_ACCESS_DISABLED: 16, USE_ANY_METHOD_AVAILABLE: 3 });
export class SecPolicy extends NativeHandle {
  static createSsl(side, hostname = null) { return new this(call("policy.ssl", { side, hostname })); }
  static createRevocation(flags) { return new this(call("policy.revocation", { flags })); }
  static createX509() { return new this(call("policy.x509")); }
}

export const TrustOptions = Object.freeze({ allowExpired: 1, leafIsCa: 2, fetchIssuerFromNet: 4, allowExpiredRoot: 8, requireRevocationPerCert: 16, useTrustSettings: 32, implicitAnchors: 64, ALLOW_EXPIRED: 1, LEAF_IS_CA: 2, FETCH_ISSUER_FROM_NET: 4, ALLOW_EXPIRED_ROOT: 8, REQUIRE_REVOCATION_PER_CERT: 16, USE_TRUST_SETTINGS: 32, IMPLICIT_ANCHORS: 64 });
export const TrustResult = Object.freeze({ DENY: "deny", FATAL_TRUST_FAILURE: "fatalTrustFailure", INVALID: "invalid", OTHER_ERROR: "otherError", PROCEED: "proceed", RECOVERABLE_TRUST_FAILURE: "recoverableTrustFailure", UNSPECIFIED: "unspecified", success: (value) => value === "proceed" || value === "unspecified" });
export class SecTrust extends NativeHandle {
  static createWithCertificates(certificates, policies) { return new this(call("trust.create", { certificates: ids(certificates), policies: ids(policies) })); }
  static copyAnchorCertificates() { return call("trust.copyAnchors").map((id) => new SecCertificate(id)); }
  setTrustVerifyDate(date) { call("trust.setVerifyDate", { handle: this.handle, timestamp: Math.floor(date.getTime() / 1000) }); return this; }
  setAnchorCertificates(certificates) { call("trust.setAnchors", { handle: this.handle, certificates: ids(certificates) }); return this; }
  setTrustAnchorCertificatesOnly(only) { call("trust.setAnchorsOnly", { handle: this.handle, only }); return this; }
  setPolicy(policy) { call("trust.setPolicy", { handle: this.handle, policy: policy.handle }); return this; }
  setOptions(flags) { call("trust.setOptions", { handle: this.handle, flags }); return this; }
  getNetworkFetchAllowed() { return call("trust.getNetworkFetchAllowed", { handle: this.handle }); }
  setNetworkFetchAllowed(allowed) { call("trust.setNetworkFetchAllowed", { handle: this.handle, allowed }); return this; }
  setTrustOcspResponse(responses) { call("trust.setOcspResponse", { handle: this.handle, responses: responses.map(toHex) }); return this; }
  setSignedCertificateTimestamps(timestamps) { call("trust.setSignedCertificateTimestamps", { handle: this.handle, timestamps: timestamps.map(toHex) }); return this; }
  copyPublicKey() { return new SecKey(call("trust.copyPublicKey", { handle: this.handle })); }
  evaluate() { return call("trust.evaluate", { handle: this.handle }); }
  evaluateWithError() { call("trust.evaluateWithError", { handle: this.handle }); }
  chain() { return call("trust.chain", { handle: this.handle }).map((id) => new SecCertificate(id)); }
  certificateCount() { return call("trust.certificateCount", { handle: this.handle }); }
  certificateAtIndex(index) { const id = call("trust.certificateAtIndex", { handle: this.handle, index }); return id == null ? null : new SecCertificate(id); }
}

export class SecRandom {
  copyBytes(length) { return fromHex(call("random.copyBytes", { length })); }
}

export class PasswordOptions {
  constructor(value) { this.value = value; }
  static generic(service, account) { return new this({ kind: "generic", service, account }); }
  static internet(server, securityDomain, account, path, port, protocol, authenticationType) { return new this({ kind: "internet", server, securityDomain, account, path, port, protocol, authenticationType }); }
  static newGenericPassword(service, account) { return this.generic(service, account); }
  static newInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType) { return this.internet(server, securityDomain, account, path, port, protocol, authenticationType); }
  setAccessControlOptions(value) { this.value.accessControlOptions = value; return this; }
  setAccessControl(value) { this.value.accessControl = value.handle; return this; }
  setAccessGroup(value) { this.value.accessGroup = value; return this; }
  setAccessSynchronized(value) { this.value.synchronized = value; return this; }
  setComment(value) { this.value.comment = value; return this; }
  setDescription(value) { this.value.description = value; return this; }
  setLabel(value) { this.value.label = value; return this; }
  useProtectedKeychain() { this.value.protectedKeychain = true; return this; }
  toDictionary() { return { ...this.value }; }
}

export function setGenericPassword(service, account, password) { call("password.setGeneric", { service, account, password: toHex(password) }); }
export function getGenericPassword(service, account) { return fromHex(call("password.getGeneric", { service, account })); }
export function deleteGenericPassword(service, account) { call("password.deleteGeneric", { service, account }); }
export function setGenericPasswordOptions(password, options) { call("password.setGenericOptions", { password: toHex(password), options: options.value }); }
export function genericPassword(options) { return fromHex(call("password.getOptions", { options: options.value })); }
export function deleteGenericPasswordOptions(options) { call("password.deleteOptions", { options: options.value }); }
export function setInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType, password) { call("password.setInternet", { server, securityDomain, account, path, port, protocol, authenticationType, password: toHex(password) }); }
export function getInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType) { return fromHex(call("password.getInternet", { server, securityDomain, account, path, port, protocol, authenticationType })); }
export function deleteInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType) { call("password.deleteInternet", { server, securityDomain, account, path, port, protocol, authenticationType }); }

const fourcc = (value) => Buffer.from(value).readUInt32BE();
const authcc = (value) => Buffer.from(value).readUInt32LE();
export const SecProtocolType = Object.freeze(Object.fromEntries(Object.entries({ FTP: "ftp ", FTPAccount: "ftpa", HTTP: "http", IRC: "irc ", NNTP: "nntp", POP3: "pop3", SMTP: "smtp", SOCKS: "sox ", IMAP: "imap", LDAP: "ldap", AppleTalk: "atlk", AFP: "afp ", Telnet: "teln", SSH: "ssh ", FTPS: "ftps", HTTPS: "htps", HTTPProxy: "htpx", HTTPSProxy: "htsx", FTPProxy: "ftpx", CIFS: "cifs", SMB: "smb ", RTSP: "rtsp", RTSPProxy: "rtsx", DAAP: "daap", EPPC: "eppc", IPP: "ipp ", NNTPS: "ntps", LDAPS: "ldps", TelnetS: "tels", IMAPS: "imps", IRCS: "ircs", POP3S: "pops", CVSpserver: "cvsp", SVN: "svn " }).map(([key, value]) => [key, fourcc(value)]).concat([["Any", 0]])));
export const SecAuthenticationType = Object.freeze(Object.fromEntries(Object.entries({ NTLM: "ntlm", MSN: "msna", DPA: "dpaa", RPA: "rpaa", HTTPBasic: "http", HTTPDigest: "httd", HTMLForm: "form", Default: "dflt" }).map(([key, value]) => [key, authcc(value)]).concat([["Any", 0]])));

export class Pkcs12ImportOptions {
  constructor() { this.value = {}; }
  passphrase(value) { this.value.passphrase = value; return this; }
  keychain(value) { this.value.keychain = value.handle; return this; }
  import(data) {
    return call("pkcs12.import", { data: toHex(data), options: this.value }).map((value) => {
      const keyId = fromHex(value.keyId);
      const certificateChain = value.certificateChain?.map((id) => new SecCertificate(id)) ?? null;
      return {
        label: value.label,
        keyId,
        key_id: keyId,
        trust: value.trust == null ? null : new SecTrust(value.trust),
        certificateChain,
        cert_chain: certificateChain,
        identity: value.identity == null ? null : new SecIdentity(value.identity),
      };
    });
  }
}

export const ItemClass = Object.freeze({ genericPassword: "genericPassword", internetPassword: "internetPassword", generic_password: "genericPassword", internet_password: "internetPassword", certificate: "certificate", key: "key", identity: "identity" });
export const KeyClass = Object.freeze({ public: "public", private: "private", symmetric: "symmetric" });
export const CloudSync = Object.freeze({ matchSyncYes: "yes", matchSyncNo: "no", matchSyncAny: "any", MatchSyncYes: "yes", MatchSyncNo: "no", MatchSyncAny: "any" });
export const Limit = Object.freeze({ All: "all", Max: (value) => value });
export class ItemSearchOptions {
  constructor() { this.value = {}; }
  keychains(values) { this.value.keychains = ids(values); return this; }
  ignoreLegacyKeychains() { this.value.ignoreLegacyKeychains = true; return this; }
  class(value) { this.value.class = value; return this; }
  caseInsensitive(value) { this.value.caseInsensitive = value; return this; }
  keyClass(value) { this.value.keyClass = value; return this; }
  loadRefs(value = true) { this.value.loadRefs = value; return this; }
  loadAttributes(value = true) { this.value.loadAttributes = value; return this; }
  loadData(value = true) { this.value.loadData = value; return this; }
  limit(value) { this.value.limit = value; return this; }
  label(value) { this.value.label = value; return this; }
  trustedOnly(value) { this.value.trustedOnly = value; return this; }
  service(value) { this.value.service = value; return this; }
  subject(value) { this.value.subject = value; return this; }
  account(value) { this.value.account = value; return this; }
  accessGroup(value) { this.value.accessGroup = value; return this; }
  cloudSync(value) { this.value.cloudSync = value; return this; }
  accessGroupToken() { this.value.accessGroupToken = true; return this; }
  publicKeyHash(value) { this.value.publicKeyHash = toHex(value); return this; }
  serialNumber(value) { this.value.serialNumber = toHex(value); return this; }
  applicationLabel(value) { this.value.applicationLabel = toHex(value); return this; }
  skipAuthenticatedItems(value = true) { this.value.skipAuthenticatedItems = value; return this; }
  toDictionary() { return { ...this.value }; }
  search() {
    return call("item.search", { options: this.value }).map((result) => {
      if (result.kind === "data") result.data = fromHex(result.data);
      if (result.kind === "reference") result.reference = result.type === "certificate" ? new SecCertificate(result.handle) : result.type === "identity" ? new SecIdentity(result.handle) : result.type === "key" ? new SecKey(result.handle) : new SecKeychainItem(result.handle);
      const simplify = () => result.kind === "attributes" ? result.attributes : null;
      Object.defineProperties(result, { simplifyDict: { value: simplify }, simplify_dict: { value: simplify } });
      return result;
    });
  }
  delete() { call("item.delete", { options: this.value }); }
}

export const ItemValue = Object.freeze({
  data: (itemClass, data) => ({ class: itemClass, data: toHex(data) }),
  key: (value) => ({ type: "key", handle: value.handle }),
  identity: (value) => ({ type: "identity", handle: value.handle }),
  certificate: (value) => ({ type: "certificate", handle: value.handle }),
});
class ItemMutationOptions {
  setAccountName(value) { this.value.accountName = value; return this; }
  setAccessGroup(value) { this.value.accessGroup = value; return this; }
  setComment(value) { this.value.comment = value; return this; }
  setDescription(value) { this.value.description = value; return this; }
  setLabel(value) { this.value.label = value; return this; }
  setLocation(value) { this.value.location = value; return this; }
  setService(value) { this.value.service = value; return this; }
}
export class ItemAddOptions extends ItemMutationOptions {
  constructor(value) { super(); this.value = { value }; }
  add() { call("item.add", { options: this.value }); }
  toDictionary() { return { ...this.value }; }
}
export class ItemUpdateOptions extends ItemMutationOptions {
  constructor() { super(); this.value = {}; }
  setValue(value) { this.value.value = value; return this; }
  setClass(value) { this.value.class = value; return this; }
  toDictionary() { return { ...this.value }; }
}
export function updateItem(search, update) { call("item.update", { search: search.value, update: update.value }); }
export function addItem(options) { options.add(); }

export class SecKeychain extends NativeHandle {
  static default() { return new this(call("keychain.default")); }
  static defaultForDomain(domain) { return new this(call("keychain.defaultForDomain", { domain })); }
  static open(path) { return new this(call("keychain.open", { path })); }
  static create(path, options = new KeychainCreateOptions()) { return new this(call("keychain.create", { path, options: options.value })); }
  static userInteractionAllowed() { return call("keychain.userInteractionAllowed"); }
  static disableUserInteraction() { return new KeychainUserInteractionLock(call("keychain.disableUserInteraction")); }
  static findGenericPassword(keychains, service, account) { const result = call("keychain.findGenericPassword", { keychains: ids(keychains ?? []), service, account }); return { password: fromHex(result.password), item: new SecKeychainItem(result.item) }; }
  static findInternetPassword(keychains, server, securityDomain, account, path, port, protocol, authenticationType) { const result = call("keychain.findInternetPassword", { keychains: ids(keychains ?? []), server, securityDomain, account, path, port, protocol, authenticationType }); return { password: fromHex(result.password), item: new SecKeychainItem(result.item) }; }
  unlock(password = null) { call("keychain.unlock", { handle: this.handle, password }); }
  setSettings(settings) { call("keychain.setSettings", { handle: this.handle, settings: settings.value }); }
  findGenericPassword(service, account) { return SecKeychain.findGenericPassword([this], service, account); }
  findInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType) { return SecKeychain.findInternetPassword([this], server, securityDomain, account, path, port, protocol, authenticationType); }
  setGenericPassword(service, account, password) { call("keychain.setGenericPassword", { handle: this.handle, service, account, password: toHex(password) }); }
  addGenericPassword(service, account, password) { call("keychain.addGenericPassword", { handle: this.handle, service, account, password: toHex(password) }); }
  setInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType, password) { call("keychain.setInternetPassword", { handle: this.handle, server, securityDomain, account, path, port, protocol, authenticationType, password: toHex(password) }); }
  addInternetPassword(server, securityDomain, account, path, port, protocol, authenticationType, password) { call("keychain.addInternetPassword", { handle: this.handle, server, securityDomain, account, path, port, protocol, authenticationType, password: toHex(password) }); }
}
export const SecPreferencesDomain = Object.freeze({ user: "user", system: "system", common: "common", dynamic: "dynamic", User: "user", System: "system", Common: "common", Dynamic: "dynamic" });
export class KeychainUserInteractionLock extends NativeHandle {}
export class KeychainCreateOptions {
  constructor() { this.value = {}; }
  password(value) { this.value.password = value; return this; }
  promptUser(value) { this.value.promptUser = value; return this; }
}
export class KeychainSettings {
  constructor() { this.value = {}; }
  setLockOnSleep(value) { this.value.lockOnSleep = value; return this; }
  setLockInterval(value) { this.value.lockInterval = value; return this; }
}
export class SecKeychainItem extends NativeHandle {
  setPassword(password) { call("keychainItem.setPassword", { handle: this.handle, password: toHex(password) }); }
  delete() { call("keychainItem.delete", { handle: this.handle }); this.dispose(); }
}

export class ImportOptions {
  constructor() { this.value = {}; }
  filename(value) { this.value.filename = value; return this; }
  pkcs12() { this.value.pkcs12 = true; return this; }
  passphrase(value) { this.value.passphrase = value; return this; }
  passphraseBytes(value) { this.value.passphraseBytes = toHex(value); return this; }
  securePassphrase(value) { this.value.securePassphrase = value; return this; }
  noAccessControl(value) { this.value.noAccessControl = value; return this; }
  alertTitle(value) { this.value.alertTitle = value; return this; }
  alertPrompt(value) { this.value.alertPrompt = value; return this; }
  keychain(value) { this.value.keychain = value.handle; return this; }
  import(data) { const result = call("import.import", { options: this.value, data: toHex(data) }); return { certificates: result.certificates.map((id) => new SecCertificate(id)), identities: result.identities.map((id) => new SecIdentity(id)), keys: result.keys.map((id) => new SecKey(id)) }; }
}
export function findGenericPassword(keychains, service, account) { return SecKeychain.findGenericPassword(keychains, service, account); }
export function findInternetPassword(keychains, server, securityDomain, account, path, port, protocol, authenticationType) { return SecKeychain.findInternetPassword(keychains, server, securityDomain, account, path, port, protocol, authenticationType); }
export const find_generic_password = findGenericPassword;
export const find_internet_password = findInternetPassword;

export const DigestType = Object.freeze({ hmacMd5: "hmacMd5", hmacSha1: "hmacSha1", hmacSha2: "hmacSha2", hmac_md5: "hmacMd5", hmac_sha1: "hmacSha1", hmac_sha2: "hmacSha2", md2: "md2", md4: "md4", md5: "md5", sha1: "sha1", sha2: "sha2" });
export class DigestBuilder {
  constructor() { this.value = {}; }
  type(value) { this.value.type = value; return this; }
  length(value) { this.value.length = value; return this; }
  hmacKey(value) { this.value.hmacKey = toHex(value); return this; }
  execute(data) { return fromHex(call("digest.execute", { options: this.value, data: toHex(data) })); }
}
export const Padding = Object.freeze({ none: "none", pkcs1: "pkcs1", pkcs5: "pkcs5", pkcs7: "pkcs7", oaep: "oaep" });
export const Mode = Object.freeze({ none: "none", ecb: "ecb", cbc: "cbc", cfb: "cfb", ofb: "ofb" });
export class EncryptBuilder {
  constructor() { this.value = {}; }
  padding(value) { this.value.padding = value; return this; }
  mode(value) { this.value.mode = value; return this; }
  iv(value) { this.value.iv = toHex(value); return this; }
  encrypt(key, data) { return fromHex(call("encryptTransform.execute", { options: this.value, key: key.handle, data: toHex(data), encrypt: true })); }
  decrypt(key, data) { return fromHex(call("encryptTransform.execute", { options: this.value, key: key.handle, data: toHex(data), encrypt: false })); }
}

export const SignedAttributes = Object.freeze({ smimeCapabilities: 1, smimeEncryptionKeyPrefs: 2, smimeMsEncryptionKeyPrefs: 4, signingTime: 8, appleCodesigningHashAgility: 16, appleCodesigningHashAgilityV2: 32, appleExpirationTime: 64, SMIME_CAPABILITIES: 1, SMIME_ENCRYPTION_KEY_PREFS: 2, SMIME_MS_ENCRYPTION_KEY_PREFS: 4, SIGNING_TIME: 8, APPLE_CODESIGNING_HASH_AGILITY: 16, APPLE_CODESIGNING_HASH_AGILITY_V2: 32, APPLE_EXPIRATION_TIME: 64 });
export const CmsCertificateChainMode = Object.freeze({ none: 0, signerOnly: 1, chain: 2, chainWithRoot: 3, chainWithRootOrFail: 4, kCMSCertificateNone: 0, kCMSCertificateSignerOnly: 1, kCMSCertificateChain: 2, kCMSCertificateChainWithRoot: 3, kCMSCertificateChainWithRootOrFail: 4 });
export class CmsEncoder extends NativeHandle {
  static create() { return new this(call("cms.encoder.create")); }
  setSignerAlgorithm(algorithm) { call("cms.encoder.setSignerAlgorithm", { handle: this.handle, algorithm }); return this; }
  addSigners(signers) { call("cms.encoder.addSigners", { handle: this.handle, signers: ids(signers) }); return this; }
  getSigners() { return call("cms.encoder.getSigners", { handle: this.handle }).map((id) => new SecIdentity(id)); }
  addRecipients(recipients) { call("cms.encoder.addRecipients", { handle: this.handle, recipients: ids(recipients) }); return this; }
  getRecipients() { return call("cms.encoder.getRecipients", { handle: this.handle }).map((id) => new SecCertificate(id)); }
  setHasDetachedContent(detached) { call("cms.encoder.setDetached", { handle: this.handle, detached }); return this; }
  getHasDetachedContent() { return call("cms.encoder.getDetached", { handle: this.handle }); }
  setEncapsulatedContentTypeOid(oid) { call("cms.encoder.setContentTypeOid", { handle: this.handle, oid }); return this; }
  getEncapsulatedContentType() { return fromHex(call("cms.encoder.getContentType", { handle: this.handle })); }
  addSupportingCerts(certificates) { call("cms.encoder.addSupportingCerts", { handle: this.handle, certificates: ids(certificates) }); return this; }
  getSupportingCerts() { return call("cms.encoder.getSupportingCerts", { handle: this.handle }).map((id) => new SecCertificate(id)); }
  addSignedAttributes(flags) { call("cms.encoder.addSignedAttributes", { handle: this.handle, flags }); return this; }
  setCertificateChainMode(mode) { call("cms.encoder.setChainMode", { handle: this.handle, mode }); return this; }
  getCertificateChainMode() { return call("cms.encoder.getChainMode", { handle: this.handle }); }
  updateContent(data) { call("cms.encoder.update", { handle: this.handle, data: toHex(data) }); return this; }
  getEncodedContent() { return fromHex(call("cms.encoder.encoded", { handle: this.handle })); }
  getSignerTimestamp(index) { return call("cms.encoder.signerTimestamp", { handle: this.handle, index }); }
  getSignerTimestampWithPolicy(policy, index) { return call("cms.encoder.signerTimestampWithPolicy", { handle: this.handle, policy, index }); }
}
export function cmsEncodeContent(signers, recipients, contentTypeOid, detached, signedAttributes, content) { return fromHex(call("cms.encode", { signers: ids(signers), recipients: ids(recipients), contentTypeOid, detached, signedAttributes, content: toHex(content) })); }
export class CmsDecoder extends NativeHandle {
  static create() { return new this(call("cms.decoder.create")); }
  updateMessage(data) { call("cms.decoder.update", { handle: this.handle, data: toHex(data) }); return this; }
  finalizeMessage() { call("cms.decoder.finalize", { handle: this.handle }); return this; }
  setDetachedContent(data) { call("cms.decoder.setDetached", { handle: this.handle, data: toHex(data) }); return this; }
  getDetachedContent() { return fromHex(call("cms.decoder.getDetached", { handle: this.handle })); }
  getNumSigners() { return call("cms.decoder.numSigners", { handle: this.handle }); }
  getSignerStatus(index, policies = []) { const result = call("cms.decoder.signerStatus", { handle: this.handle, index, policies: ids(policies) }); return { ...result, trust: new SecTrust(result.trust) }; }
  getSignerEmailAddress(index) { return call("cms.decoder.signerEmail", { handle: this.handle, index }); }
  isContentEncrypted() { return call("cms.decoder.isEncrypted", { handle: this.handle }); }
  getEncapsulatedContentType() { return fromHex(call("cms.decoder.contentType", { handle: this.handle })); }
  getAllCerts() { return call("cms.decoder.allCerts", { handle: this.handle }).map((id) => new SecCertificate(id)); }
  getContent() { return fromHex(call("cms.decoder.content", { handle: this.handle })); }
  getSignerSigningTime(index) { return call("cms.decoder.signingTime", { handle: this.handle, index }); }
  getSignerTimestamp(index) { return call("cms.decoder.signerTimestamp", { handle: this.handle, index }); }
  getSignerTimestampWithPolicy(policy, index) { return call("cms.decoder.signerTimestampWithPolicy", { handle: this.handle, policy, index }); }
  getSignerTimestampCertificates(index) { return call("cms.decoder.timestampCertificates", { handle: this.handle, index }).map((id) => new SecCertificate(id)); }
}

export const TrustSettingsDomain = Object.freeze({ user: "user", admin: "admin", system: "system", User: "user", Admin: "admin", System: "system" });
export const TrustSettingsForCertificate = Object.freeze({ TrustRoot: "TrustRoot", TrustAsRoot: "TrustAsRoot", Deny: "Deny", Unspecified: "Unspecified", Invalid: "Invalid" });
export class TrustSettings {
  constructor(domain) { this.domain = domain; }
  certificates() { return call("trustSettings.iter", { domain: this.domain }).map((id) => new SecCertificate(id)); }
  iter() { return this[Symbol.iterator](); }
  setTrustSettingsAlways(certificate) { call("trustSettings.setAlways", { domain: this.domain, certificate: certificate.handle }); }
  tlsTrustSettingsForCertificate(certificate) { return call("trustSettings.forCertificate", { domain: this.domain, certificate: certificate.handle }); }
  *[Symbol.iterator]() { yield* this.certificates(); }
}

export const CodeSigningFlags = Object.freeze({
  none: 0, checkAllArchitectures: 1 << 0, doNotValidateExecutable: 1 << 1,
  doNotValidateResources: 1 << 2, basicValidateOnly: 3, checkNestedCode: 1 << 3,
  strictValidate: 1 << 4, fullReport: 1 << 5, checkGatekeeperArchitectures: (1 << 6) | 1,
  restrictSymlinks: 1 << 7, restrictToAppLike: 1 << 8, restrictSidebandData: 1 << 9,
  useSoftwareSigningCert: 1 << 10, validatePeh: 1 << 11, singleThreaded: 1 << 12,
  quickCheck: 1 << 26, checkTrustedAnchors: 1 << 27, reportProgress: 1 << 28,
  noNetworkAccess: 1 << 29, enforceRevocationChecks: 1 << 30, considerExpiration: 2 ** 31,
  NONE: 0, CHECK_ALL_ARCHITECTURES: 1 << 0, DO_NOT_VALIDATE_EXECUTABLE: 1 << 1,
  DO_NOT_VALIDATE_RESOURCES: 1 << 2, BASIC_VALIDATE_ONLY: 3, CHECK_NESTED_CODE: 1 << 3,
  STRICT_VALIDATE: 1 << 4, FULL_REPORT: 1 << 5, CHECK_GATEKEEPER_ARCHITECTURES: (1 << 6) | 1,
  RESTRICT_SYMLINKS: 1 << 7, RESTRICT_TO_APP_LIKE: 1 << 8, RESTRICT_SIDEBAND_DATA: 1 << 9,
  USE_SOFTWARE_SIGNING_CERT: 1 << 10, VALIDATE_PEH: 1 << 11, SINGLE_THREADED: 1 << 12,
  QUICK_CHECK: 1 << 26, CHECK_TRUSTED_ANCHORS: 1 << 27, REPORT_PROGRESS: 1 << 28,
  NO_NETWORK_ACCESS: 1 << 29, ENFORCE_REVOCATION_CHECKS: 1 << 30, CONSIDER_EXPIRATION: 2 ** 31,
});
export class SecRequirement extends NativeHandle {
  static parse(requirement) { return new this(call("codeSigning.requirement", { requirement })); }
}
export class GuestAttributes {
  constructor() { this.value = {}; }
  setPid(pid) { this.value.pid = pid; return this; }
  setAuditToken(value) { this.value.auditToken = toHex(value); return this; }
  setOther(key, value) { (this.value.other ??= {})[key] = value; return this; }
}
export class SecCode extends NativeHandle {
  static forSelf(flags = 0) { return new this(call("codeSigning.self", { flags })); }
  static copyGuestWithAttributes(host, attributes, flags = 0) { return new this(call("codeSigning.guest", { host: host?.handle, attributes: attributes.value, flags })); }
  checkValidity(flags, requirement) { call("codeSigning.codeValidity", { handle: this.handle, flags, requirement: requirement.handle }); }
  path(flags = 0) { return call("codeSigning.codePath", { handle: this.handle, flags }); }
}
export class SecStaticCode extends NativeHandle {
  static fromPath(path, flags = 0) { return new this(call("codeSigning.staticFromPath", { path, flags })); }
  checkValidity(flags, requirement) { call("codeSigning.staticValidity", { handle: this.handle, flags, requirement: requirement.handle }); }
  path(flags = 0) { return call("codeSigning.staticPath", { handle: this.handle, flags }); }
}

export const AuthorizationFlags = Object.freeze({ defaults: 0, interactionAllowed: 1 << 0, extendRights: 1 << 1, partialRights: 1 << 2, destroyRights: 1 << 3, preauthorize: 1 << 4, DEFAULTS: 0, INTERACTION_ALLOWED: 1 << 0, EXTEND_RIGHTS: 1 << 1, PARTIAL_RIGHTS: 1 << 2, DESTROY_RIGHTS: 1 << 3, PREAUTHORIZE: 1 << 4 });
export class AuthorizationItemSetBuilder {
  constructor() { this.items = []; }
  addRight(name) { this.items.push({ name }); return this; }
  addData(name, value) { this.items.push({ name, value: toHex(value) }); return this; }
  addString(name, value) { this.items.push({ name, value, string: true }); return this; }
  build() { return this.items; }
}
export class Authorization extends NativeHandle {
  static create(rights = null, environment = null, flags = 0) { return new this(call("authorization.create", { rights, environment, flags })); }
  static default() { return this.create(); }
  static fromExternalForm(data) { return new this(call("authorization.fromExternalForm", { data: toHex(data) })); }
  static rightExists(name) { return call("authorization.rightExists", { name }); }
  static getRight(name) { return call("authorization.getRight", { name }); }
  destroyRights() { call("authorization.destroyRights", { handle: this.handle }); this.handle = 0; }
  removeRight(name) { call("authorization.removeRight", { handle: this.handle, name }); }
  setRight(name, existingRight, description = null, locale = null) { call("authorization.setRight", { handle: this.handle, name, existingRight, description, locale }); }
  copyInfo(tag = null) { return call("authorization.copyInfo", { handle: this.handle, tag }); }
  makeExternalForm() { return fromHex(call("authorization.makeExternalForm", { handle: this.handle })); }
  executeWithPrivileges(command, args = [], flags = 0) { call("authorization.execute", { handle: this.handle, command, arguments: args, flags, piped: false }); }
  executeWithPrivilegesPiped(command, args = [], flags = 0) { return fromHex(call("authorization.execute", { handle: this.handle, command, arguments: args, flags, piped: true })); }
  jobBless(label) { call("authorization.jobBless", { handle: this.handle, label }); }
}

export const SslProtocolSide = Object.freeze({ client: "client", server: "server", CLIENT: "client", SERVER: "server" });
export const SslConnectionType = Object.freeze({ stream: "stream", datagram: "datagram", STREAM: "stream", DATAGRAM: "datagram" });
export const SslProtocol = Object.freeze({ all: "all", dtls1: "dtls1", ssl2: "ssl2", ssl3: "ssl3", ssl3Only: "ssl3Only", tls1: "tls1", tls11: "tls11", tls12: "tls12", tls13: "tls13", tls1Only: "tls1Only", unknown: "unknown", ALL: "all", DTLS1: "dtls1", SSL2: "ssl2", SSL3: "ssl3", SSL3_ONLY: "ssl3Only", TLS1: "tls1", TLS11: "tls11", TLS12: "tls12", TLS13: "tls13", TLS1_ONLY: "tls1Only", UNKNOWN: "unknown" });
export const SslAuthenticate = Object.freeze({ always: "always", never: "never", try: "try", ALWAYS: "always", NEVER: "never", TRY: "try" });
export const SessionState = Object.freeze({ ABORTED: "aborted", CLOSED: "closed", CONNECTED: "connected", HANDSHAKE: "handshake", IDLE: "idle" });
export const SslClientCertificateState = Object.freeze({ NONE: "none", REJECTED: "rejected", REQUESTED: "requested", SENT: "sent" });
export const CipherSuite = Object.freeze({ ...CipherSuites, fromRaw: (raw) => raw, toRaw: (suite) => suite, from_raw: (raw) => raw, to_raw: (suite) => suite });

function handshakeResult(result) {
  if (result.kind === "stream") return new SslStream(result.handle);
  if (result.kind === "interrupted") throw new HandshakeError(result.error, new MidHandshakeSslStream(result.handle));
  throw new HandshakeError(result.error);
}

function clientHandshakeResult(result) {
  if (result.kind === "stream") return new SslStream(result.handle);
  if (result.kind === "interrupted") throw new ClientHandshakeError(result.error, new MidHandshakeClientBuilder(result.handle));
  throw new ClientHandshakeError(result.error);
}

export class MidHandshakeSslStream extends NativeHandle {
  getRef() { return call("ssl.midStream.info", { handle: this.handle }); }
  getMut() { return this.getRef(); }
  context() { return new SslContext(call("ssl.midStream.context", { handle: this.handle })); }
  contextMut() { return this.context(); }
  error() { return new SecurityFrameworkError(call("ssl.midStream.state", { handle: this.handle }).error); }
  serverAuthCompleted() { return call("ssl.midStream.state", { handle: this.handle }).serverAuthCompleted; }
  clientCertRequested() { return call("ssl.midStream.state", { handle: this.handle }).clientCertRequested; }
  wouldBlock() { return call("ssl.midStream.state", { handle: this.handle }).wouldBlock; }
  clientHelloReceived() { return call("ssl.midStream.state", { handle: this.handle }).clientHelloReceived; }
  handshake() { return handshakeResult(call("ssl.midStream.handshake", { handle: this._takeHandle() })); }
}

export class MidHandshakeClientBuilder extends NativeHandle {
  getRef() { return call("ssl.midClient.info", { handle: this.handle }); }
  getMut() { return this.getRef(); }
  error() { return new SecurityFrameworkError(call("ssl.midClient.error", { handle: this.handle })); }
  handshake() { return clientHandshakeResult(call("ssl.midClient.handshake", { handle: this._takeHandle() })); }
}

export class SslContext extends NativeHandle {
  static create(side, connectionType = SslConnectionType.stream) { return new this(call("ssl.context.create", { side, connectionType })); }
  setPeerDomainName(name) { call("ssl.context.setPeerDomainName", { handle: this.handle, name }); return this; }
  peerDomainName() { return call("ssl.context.peerDomainName", { handle: this.handle }); }
  setCertificate(identity, certificates = []) { call("ssl.context.setCertificate", { handle: this.handle, identity: identity.handle, certificates: ids(certificates) }); return this; }
  setPeerId(data) { call("ssl.context.setPeerId", { handle: this.handle, data: toHex(data) }); return this; }
  peerId() { return fromHex(call("ssl.context.peerId", { handle: this.handle })); }
  supportedCiphers() { return call("ssl.context.supportedCiphers", { handle: this.handle }); }
  enabledCiphers() { return call("ssl.context.enabledCiphers", { handle: this.handle }); }
  setEnabledCiphers(ciphers) { call("ssl.context.setEnabledCiphers", { handle: this.handle, ciphers }); return this; }
  negotiatedCipher() { return call("ssl.context.negotiatedCipher", { handle: this.handle }); }
  setClientSideAuthenticate(auth) { call("ssl.context.setClientAuthenticate", { handle: this.handle, auth }); return this; }
  clientCertificateState() { return call("ssl.context.clientCertificateState", { handle: this.handle }); }
  peerTrust() { const id = call("ssl.context.peerTrust", { handle: this.handle }); return id == null ? null : new SecTrust(id); }
  peerTrust2() { return this.peerTrust(); }
  state() { return call("ssl.context.state", { handle: this.handle }); }
  negotiatedProtocolVersion() { return call("ssl.context.negotiatedProtocol", { handle: this.handle }); }
  protocolVersionMax() { return call("ssl.context.protocolMax", { handle: this.handle }); }
  setProtocolVersionMax(protocol) { call("ssl.context.setProtocolMax", { handle: this.handle, protocol }); return this; }
  protocolVersionMin() { return call("ssl.context.protocolMin", { handle: this.handle }); }
  setProtocolVersionMin(protocol) { call("ssl.context.setProtocolMin", { handle: this.handle, protocol }); return this; }
  alpnProtocols() { return call("ssl.context.alpnProtocols", { handle: this.handle }); }
  setAlpnProtocols(protocols) { call("ssl.context.setAlpnProtocols", { handle: this.handle, protocols }); return this; }
  setSessionTicketsEnabled(enabled) { call("ssl.context.setSessionTicketsEnabled", { handle: this.handle, enabled }); return this; }
  bufferedReadSize() { return call("ssl.context.bufferedReadSize", { handle: this.handle }); }
  getOption(option) { return call("ssl.context.getOption", { handle: this.handle, option }); }
  setOption(option, enabled) { call("ssl.context.setOption", { handle: this.handle, option, enabled }); return this; }
  diffieHellmanParams() { return fromHex(call("ssl.context.diffieHellmanParams", { handle: this.handle })); }
  setDiffieHellmanParams(data) { call("ssl.context.setDiffieHellmanParams", { handle: this.handle, data: toHex(data) }); return this; }
  certificateAuthorities() { const result = call("ssl.context.certificateAuthorities", { handle: this.handle }); return result?.map((id) => new SecCertificate(id)) ?? null; }
  setCertificateAuthorities(certificates) { call("ssl.context.setCertificateAuthorities", { handle: this.handle, certificates: ids(certificates), add: false }); return this; }
  addCertificateAuthorities(certificates) { call("ssl.context.setCertificateAuthorities", { handle: this.handle, certificates: ids(certificates), add: true }); return this; }
  connect(host, port) { return handshakeResult(call("ssl.context.connect", { handle: this._takeHandle(), host, port })); }
  handshake(host, port) { return this.connect(host, port); }
}
for (const option of ["breakOnServerAuth", "breakOnCertRequested", "breakOnClientAuth", "falseStart", "sendOneByteRecord", "allowServerIdentityChange", "fallback", "breakOnClientHello"]) {
  const suffix = option[0].toUpperCase() + option.slice(1);
  SslContext.prototype[option] = function () { return this.getOption(option); };
  SslContext.prototype[`set${suffix}`] = function (value) { return this.setOption(option, value); };
}
export class SslStream extends NativeHandle {
  read(length) { return fromHex(call("ssl.stream.read", { handle: this.handle, length })); }
  write(data) { return call("ssl.stream.write", { handle: this.handle, data: toHex(data) }); }
  flush() { call("ssl.stream.flush", { handle: this.handle }); }
  close() { call("ssl.stream.close", { handle: this.handle }); }
  context() { return new SslContext(call("ssl.stream.context", { handle: this.handle })); }
  contextMut() { return this.context(); }
  getRef() { return call("ssl.stream.info", { handle: this.handle }); }
  getMut() { return this.getRef(); }
}
export class ClientBuilder {
  constructor() { this.value = {}; }
  anchorCertificates(values) { this.value.anchorCertificates = ids(values); return this; }
  addAnchorCertificate(value) { this.value.anchorCertificates = [...(this.value.anchorCertificates ?? []), value.handle]; return this; }
  trustAnchorCertificatesOnly(value) { this.value.trustAnchorCertificatesOnly = value; return this; }
  dangerAcceptInvalidCerts(value) { this.value.dangerAcceptInvalidCerts = value; return this; }
  useSni(value) { this.value.useSni = value; return this; }
  dangerAcceptInvalidHostnames(value) { this.value.dangerAcceptInvalidHostnames = value; return this; }
  whitelistCiphers(value) { this.value.whitelistCiphers = value; return this; }
  blacklistCiphers(value) { this.value.blacklistCiphers = value; return this; }
  identity(value, chain = []) { this.value.identity = { handle: value.handle, chain: ids(chain) }; return this; }
  protocolMin(value) { this.value.protocolMin = value; return this; }
  protocolMax(value) { this.value.protocolMax = value; return this; }
  alpnProtocols(value) { this.value.alpnProtocols = value; return this; }
  enableSessionTickets(value) { this.value.enableSessionTickets = value; return this; }
  connect(domain, host, port) { return clientHandshakeResult(call("ssl.client.connect", { domain, host, port, options: this.value })); }
  handshake(domain, host, port) { return this.connect(domain, host, port); }
}
export class ServerBuilder {
  constructor(identity, certificates = []) { this.value = { identity: identity.handle, certificates: ids(certificates) }; }
  static fromPkcs12(data, passphrase) { const value = Object.create(this.prototype); value.value = { pkcs12: toHex(data), passphrase }; return value; }
  newSslContext() { return new SslContext(call("ssl.server.context", { options: this.value })); }
  handshake(host, port) { return new SslStream(call("ssl.server.accept", { options: this.value, host, port })); }
}

// Exact Rust spellings are aliases, so ported Rust examples can be translated mechanically.
function aliases(type, values, statics = {}) {
  for (const [alias, original] of Object.entries(values)) Object.defineProperty(type.prototype, alias, { value: type.prototype[original] });
  for (const [alias, original] of Object.entries(statics)) Object.defineProperty(type, alias, { value: type[original] });
}
aliases(SecAccessControl, {}, { create_with_flags: "createWithFlags", create_with_protection: "createWithProtection" });
aliases(SecCertificate, { to_der: "toDer", add_to_keychain: "addToKeychain", subject_summary: "subjectSummary", email_addresses: "emailAddresses", serial_number_bytes: "serialNumberBytes", public_key_info_der: "publicKeyInfoDer", public_key: "publicKey", common_name: "commonName" }, { from_der: "fromDer" });
aliases(SecIdentity, { private_key: "privateKey" }, { with_certificate: "withCertificate" });
aliases(SecKey, { application_label: "applicationLabel", external_representation: "externalRepresentation", public_key: "publicKey", encrypt_data: "encryptData", decrypt_data: "decryptData", create_signature: "createSignature", verify_signature: "verifySignature", key_exchange: "keyExchange" }, { from_data: "fromData", new: "generate" });
aliases(SecPolicy, {}, { create_ssl: "createSsl", create_revocation: "createRevocation", create_x509: "createX509" });
aliases(SecTrust, { set_trust_verify_date: "setTrustVerifyDate", set_anchor_certificates: "setAnchorCertificates", set_trust_anchor_certificates_only: "setTrustAnchorCertificatesOnly", set_policy: "setPolicy", set_options: "setOptions", get_network_fetch_allowed: "getNetworkFetchAllowed", set_network_fetch_allowed: "setNetworkFetchAllowed", set_trust_ocsp_response: "setTrustOcspResponse", set_signed_certificate_timestamps: "setSignedCertificateTimestamps", copy_public_key: "copyPublicKey", evaluate_with_error: "evaluateWithError", certificate_count: "certificateCount", certificate_at_index: "certificateAtIndex" }, { create_with_certificates: "createWithCertificates", copy_anchor_certificates: "copyAnchorCertificates" });
aliases(SecCode, {}, { copy_guest_with_attribues: "copyGuestWithAttributes" });
aliases(DigestBuilder, { type_: "type" });
aliases(ItemSearchOptions, { pub_key_hash: "publicKeyHash" });

for (const [type, create] of [
  [AuthorizationItemSetBuilder, function () { return new this(); }],
  [ItemSearchOptions, function () { return new this(); }],
  [ItemAddOptions, function (value) { return new this(value); }],
  [ItemUpdateOptions, function () { return new this(); }],
  [Pkcs12ImportOptions, function () { return new this(); }],
  [KeychainCreateOptions, function () { return new this(); }],
  [KeychainSettings, function () { return new this(); }],
  [ImportOptions, function () { return new this(); }],
  [DigestBuilder, function () { return new this(); }],
  [EncryptBuilder, function () { return new this(); }],
  [TrustSettings, function (domain) { return new this(domain); }],
  [GuestAttributes, function () { return new this(); }],
  [ClientBuilder, function () { return new this(); }],
  [ServerBuilder, function (identity, certificates = []) { return new this(identity, certificates); }],
]) Object.defineProperty(type, "new", { value: create });
Object.defineProperty(SslContext, "new", { value: SslContext.create });
Object.defineProperty(Authorization, "new", { value: Authorization.create });

const snake = (name) => name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
function installRustAliases(type) {
  for (const name of Object.getOwnPropertyNames(type.prototype)) {
    const alias = snake(name);
    if (name !== "constructor" && alias !== name && typeof type.prototype[name] === "function" && !(alias in type.prototype)) Object.defineProperty(type.prototype, alias, { value: type.prototype[name] });
  }
  for (const name of Object.getOwnPropertyNames(type)) {
    const alias = snake(name);
    if (!["length", "name", "prototype"].includes(name) && alias !== name && typeof type[name] === "function" && !(alias in type)) Object.defineProperty(type, alias, { value: type[name] });
  }
}
[
  SecurityFrameworkError, SecAccessControl, SecCertificate, CertificateProperties, SecIdentity, GenerateKeyOptions, SecKey, SecPolicy, SecTrust,
  SecRandom, PasswordOptions, Pkcs12ImportOptions, ItemSearchOptions, ItemMutationOptions, ItemAddOptions,
  ItemUpdateOptions, SecKeychain, KeychainCreateOptions, KeychainSettings, SecKeychainItem,
  ImportOptions, DigestBuilder, EncryptBuilder, CmsEncoder, CmsDecoder, TrustSettings,
  SecRequirement, GuestAttributes, SecCode, SecStaticCode, AuthorizationItemSetBuilder, Authorization,
  MidHandshakeSslStream, MidHandshakeClientBuilder, SslContext, SslStream, ClientBuilder, ServerBuilder,
].forEach(installRustAliases);

export const passwords = Object.freeze({ PasswordOptions, AccessControlOptions, setGenericPassword, getGenericPassword, deleteGenericPassword, setGenericPasswordOptions, genericPassword, deleteGenericPasswordOptions, setInternetPassword, getInternetPassword, deleteInternetPassword, set_generic_password: setGenericPassword, get_generic_password: getGenericPassword, delete_generic_password: deleteGenericPassword, set_generic_password_options: setGenericPasswordOptions, generic_password: genericPassword, delete_generic_password_options: deleteGenericPasswordOptions, set_internet_password: setInternetPassword, get_internet_password: getInternetPassword, delete_internet_password: deleteInternetPassword });
export const cms = Object.freeze({ CmsEncoder, CmsDecoder, CMSEncoder: CmsEncoder, CMSDecoder: CmsDecoder, SignedAttributes, CmsCertificateChainMode, encodeContent: cmsEncodeContent, cms_encode_content: cmsEncodeContent, CMS_DIGEST_ALGORITHM_SHA1: "sha1", CMS_DIGEST_ALGORITHM_SHA256: "sha256" });

export const set_generic_password = setGenericPassword;
export const get_generic_password = getGenericPassword;
export const delete_generic_password = deleteGenericPassword;
export const set_generic_password_options = setGenericPasswordOptions;
export const generic_password = genericPassword;
export const delete_generic_password_options = deleteGenericPasswordOptions;
export const set_internet_password = setInternetPassword;
export const get_internet_password = getInternetPassword;
export const delete_internet_password = deleteInternetPassword;
export const add_item = addItem;
export const update_item = updateItem;
export const cms_encode_content = cmsEncodeContent;
export const CMSEncoder = CmsEncoder;
export const CMSDecoder = CmsDecoder;

export const access_control = Object.freeze({ SecAccessControl, ProtectionMode });
export const authorization = Object.freeze({ Authorization, AuthorizationItemSetBuilder, Flags: AuthorizationFlags });
export const base = Object.freeze({ Error: SecurityFrameworkError });
export const certificate = Object.freeze({ SecCertificate, CertificateOid, CertificateProperties });
export const cipher_suite = Object.freeze({ CipherSuite });
export const identity = Object.freeze({ SecIdentity });
export const import_export = Object.freeze({ Pkcs12ImportOptions, ImportOptions });
export const item = Object.freeze({ ItemClass, KeyClass, Limit, CloudSync, ItemSearchOptions, ItemAddOptions, ItemUpdateOptions, ItemValue, Location, addItem, add_item, updateItem, update_item });
export const key = Object.freeze({ SecKey, KeyType, Algorithm, Token, GenerateKeyOptions });
export const policy = Object.freeze({ SecPolicy, RevocationPolicy });
export const random = Object.freeze({ SecRandom });
export const secure_transport = Object.freeze({ HandshakeError, ClientHandshakeError, MidHandshakeSslStream, MidHandshakeClientBuilder, SslContext, SslStream, ClientBuilder, ServerBuilder, SslProtocol, SslProtocolSide, SslConnectionType, SslAuthenticate, SessionState, SslClientCertificateState });
export const trust = Object.freeze({ SecTrust, TrustOptions, TrustResult });
export const trust_settings = Object.freeze({ TrustSettings, Domain: TrustSettingsDomain, TrustSettingsForCertificate });
export const os = Object.freeze({ macos: Object.freeze({ certificate: { SecCertificate, CertificateProperties }, certificate_oids: { CertificateOid }, code_signing: { GuestAttributes, SecRequirement, SecCode, SecStaticCode, Flags: CodeSigningFlags }, digest_transform: { Builder: DigestBuilder, DigestType }, encrypt_transform: { Builder: EncryptBuilder, Padding, Mode }, identity: { SecIdentity }, import_export: { Pkcs12ImportOptions, ImportOptions }, item: { ItemSearchOptions }, key: { SecKey, KeyType }, passwords: { find_generic_password, find_internet_password }, keychain: { SecKeychain, CreateOptions: KeychainCreateOptions, KeychainSettings }, secure_transport: { SslContext, MidHandshakeSslStream } }) });
