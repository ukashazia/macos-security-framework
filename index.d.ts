/// Complete macOS bindings corresponding to security-framework 3.7.0.

export type Binary = string | ArrayBuffer | ArrayBufferView;
export type EnumValues<T> = T[keyof T];

export class SecurityFrameworkError extends Error {
  readonly code?: number;
  static message(code: number): string | null;
  static fromCode(code: number): SecurityFrameworkError;
  static from_code: typeof SecurityFrameworkError.fromCode;
}
export class HandshakeError extends SecurityFrameworkError {
  readonly kind: "failure" | "interrupted";
  readonly stream: MidHandshakeSslStream | null;
}
export class ClientHandshakeError extends SecurityFrameworkError {
  readonly kind: "failure" | "interrupted";
  readonly builder: MidHandshakeClientBuilder | null;
}

interface DisposableNative {
  readonly handle: number;
  dispose(): void;
}

export const ProtectionMode: Readonly<Record<"accessibleWhenPasscodeSetThisDeviceOnly" | "accessibleWhenUnlockedThisDeviceOnly" | "accessibleWhenUnlocked" | "accessibleAfterFirstUnlockThisDeviceOnly" | "accessibleAfterFirstUnlock", string>>;
export const AccessControlOptions: Readonly<Record<string, number>>;
export class SecAccessControl implements DisposableNative {
  readonly handle: number;
  static createWithFlags(flags: number): SecAccessControl;
  static createWithProtection(protection: EnumValues<typeof ProtectionMode> | null, flags?: number): SecAccessControl;
  static create_with_flags: typeof SecAccessControl.createWithFlags;
  static create_with_protection: typeof SecAccessControl.createWithProtection;
  dispose(): void;
}

export interface CertificateProperty { label: string; value: { type: "string"; value: string } | { type: "section"; value: CertificateProperty[] } | { type: "unknown" } }
export const CertificateOid: Readonly<{ x509V1SignatureAlgorithm: string; x509_v1_signature_algorithm: string }>;
export class CertificateProperties { get(oid: string): CertificateProperty | null }
export class SecCertificate implements DisposableNative {
  readonly handle: number;
  static fromDer(data: Binary): SecCertificate;
  static from_der: typeof SecCertificate.fromDer;
  toDer(): Buffer;
  addToKeychain(keychain?: SecKeychain | null): void;
  subjectSummary(): string;
  emailAddresses(): string[];
  issuer(): Buffer;
  subject(): Buffer;
  serialNumberBytes(): Buffer;
  publicKeyInfoDer(): Buffer | null;
  publicKey(): SecKey;
  commonName(): string;
  fingerprint(): Buffer;
  signatureAlgorithmProperty(): CertificateProperty | null;
  properties(keys?: string[] | null): CertificateProperties;
  delete(): void;
  dispose(): void;
}

export class SecIdentity implements DisposableNative {
  readonly handle: number;
  static withCertificate(keychains: SecKeychain[], certificate: SecCertificate): SecIdentity;
  static with_certificate: typeof SecIdentity.withCertificate;
  certificate(): SecCertificate;
  privateKey(): SecKey;
  delete(): void;
  dispose(): void;
}

export const KeyType: Readonly<Record<string, string>>;
export const Token: Readonly<Record<string, string>>;
export const Location: Readonly<Record<string, string>>;
export function fileKeychainLocation(keychain: SecKeychain): { fileKeychain: number };
export const Algorithm: Readonly<Record<string, string>>;
export class GenerateKeyOptions {
  setKeyType(value: EnumValues<typeof KeyType>): this;
  setSizeInBits(value: number): this;
  setLabel(value: string): this;
  setToken(value: EnumValues<typeof Token>): this;
  setLocation(value: EnumValues<typeof Location>): this;
  setAccessControl(value: SecAccessControl): this;
  setSynchronizable(value: boolean): this;
  toDictionary(): Record<string, unknown>;
}
export class SecKey implements DisposableNative {
  readonly handle: number;
  static generate(options?: GenerateKeyOptions): SecKey;
  static new(options?: GenerateKeyOptions): SecKey;
  static fromData(keyType: EnumValues<typeof KeyType>, data: Binary): SecKey;
  static from_data: typeof SecKey.fromData;
  applicationLabel(): Buffer | null;
  attributes(): Record<string, string>;
  externalRepresentation(): Buffer | null;
  publicKey(): SecKey | null;
  encryptData(algorithm: string, data: Binary): Buffer;
  decryptData(algorithm: string, data: Binary): Buffer;
  createSignature(algorithm: string, data: Binary): Buffer;
  verifySignature(algorithm: string, data: Binary, signature: Binary): boolean;
  keyExchange(algorithm: string, publicKey: SecKey, requestedSize: number, sharedInfo?: Binary | null): Buffer;
  delete(): void;
  dispose(): void;
}

export const RevocationPolicy: Readonly<Record<string, number>>;
export class SecPolicy implements DisposableNative {
  readonly handle: number;
  static createSsl(side: "client" | "server", hostname?: string | null): SecPolicy;
  static createRevocation(flags: number): SecPolicy;
  static createX509(): SecPolicy;
  static create_ssl: typeof SecPolicy.createSsl;
  static create_revocation: typeof SecPolicy.createRevocation;
  static create_x509: typeof SecPolicy.createX509;
  dispose(): void;
}
export const TrustOptions: Readonly<Record<string, number>>;
export const TrustResult: Readonly<Record<string, string | ((value: string) => boolean)>>;
export interface TrustEvaluation { success: boolean; debug: string }
export class SecTrust implements DisposableNative {
  readonly handle: number;
  static createWithCertificates(certificates: SecCertificate[], policies: SecPolicy[]): SecTrust;
  static copyAnchorCertificates(): SecCertificate[];
  static create_with_certificates: typeof SecTrust.createWithCertificates;
  static copy_anchor_certificates: typeof SecTrust.copyAnchorCertificates;
  setTrustVerifyDate(date: Date): this;
  setAnchorCertificates(certificates: SecCertificate[]): this;
  setTrustAnchorCertificatesOnly(only: boolean): this;
  setPolicy(policy: SecPolicy): this;
  setOptions(flags: number): this;
  getNetworkFetchAllowed(): boolean;
  setNetworkFetchAllowed(allowed: boolean): this;
  setTrustOcspResponse(responses: Binary[]): this;
  setSignedCertificateTimestamps(timestamps: Binary[]): this;
  copyPublicKey(): SecKey;
  evaluate(): TrustEvaluation;
  evaluateWithError(): void;
  chain(): SecCertificate[];
  certificateCount(): number;
  certificateAtIndex(index: number): SecCertificate | null;
  dispose(): void;
}
export class SecRandom { copyBytes(length: number): Buffer }

export const SecProtocolType: Readonly<Record<string, number>>;
export const SecAuthenticationType: Readonly<Record<string, number>>;
export class PasswordOptions {
  static generic(service: string, account: string): PasswordOptions;
  static internet(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): PasswordOptions;
  static newGenericPassword(service: string, account: string): PasswordOptions;
  static newInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): PasswordOptions;
  static new_generic_password: typeof PasswordOptions.newGenericPassword;
  static new_internet_password: typeof PasswordOptions.newInternetPassword;
  setAccessControlOptions(value: number): this;
  setAccessControl(value: SecAccessControl): this;
  setAccessGroup(value: string): this;
  setAccessSynchronized(value: boolean | null): this;
  setComment(value: string): this;
  setDescription(value: string): this;
  setLabel(value: string): this;
  useProtectedKeychain(): this;
  toDictionary(): Record<string, unknown>;
}
export function setGenericPassword(service: string, account: string, password: Binary): void;
export function getGenericPassword(service: string, account: string): Buffer;
export function deleteGenericPassword(service: string, account: string): void;
export function setGenericPasswordOptions(password: Binary, options: PasswordOptions): void;
export function genericPassword(options: PasswordOptions): Buffer;
export function deleteGenericPasswordOptions(options: PasswordOptions): void;
export function setInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number, password: Binary): void;
export function getInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): Buffer;
export function deleteInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): void;
export const set_generic_password: typeof setGenericPassword;
export const get_generic_password: typeof getGenericPassword;
export const delete_generic_password: typeof deleteGenericPassword;
export const set_generic_password_options: typeof setGenericPasswordOptions;
export const generic_password: typeof genericPassword;
export const delete_generic_password_options: typeof deleteGenericPasswordOptions;
export const set_internet_password: typeof setInternetPassword;
export const get_internet_password: typeof getInternetPassword;
export const delete_internet_password: typeof deleteInternetPassword;

export interface ImportedIdentity { label: string | null; keyId: Buffer | null; key_id: Buffer | null; trust: SecTrust | null; certificateChain: SecCertificate[] | null; cert_chain: SecCertificate[] | null; identity: SecIdentity | null }
export class Pkcs12ImportOptions {
  static new(): Pkcs12ImportOptions;
  passphrase(value: string): this;
  keychain(value: SecKeychain): this;
  import(data: Binary): ImportedIdentity[];
}
export interface SecItems { certificates: SecCertificate[]; identities: SecIdentity[]; keys: SecKey[] }
export class ImportOptions {
  static new(): ImportOptions;
  filename(value: string): this;
  pkcs12(): this;
  passphrase(value: string): this;
  passphraseBytes(value: Binary): this;
  securePassphrase(value: boolean): this;
  noAccessControl(value: boolean): this;
  alertTitle(value: string): this;
  alertPrompt(value: string): this;
  keychain(value: SecKeychain): this;
  import(data: Binary): SecItems;
}

export const ItemClass: Readonly<Record<string, string>>;
export const KeyClass: Readonly<Record<"public" | "private" | "symmetric", string>>;
export const CloudSync: Readonly<Record<string, string>>;
export const Limit: Readonly<{ All: "all"; Max(value: number): number }>;
export type ItemReference = { type: "key" | "identity" | "certificate"; handle: number };
export type ItemData = { class: string; data: string };
export const ItemValue: Readonly<{ data(itemClass: string, data: Binary): ItemData; key(value: SecKey): ItemReference; identity(value: SecIdentity): ItemReference; certificate(value: SecCertificate): ItemReference }>;
export interface SearchResultMethods { simplifyDict(): Record<string, string> | null; simplify_dict(): Record<string, string> | null }
export type SearchResult = ({ kind: "data"; data: Buffer } | { kind: "attributes"; attributes: Record<string, string> } | { kind: "reference"; type: string; reference: SecCertificate | SecIdentity | SecKey | SecKeychainItem } | { kind: "other" }) & SearchResultMethods;
export class ItemSearchOptions {
  static new(): ItemSearchOptions;
  keychains(values: SecKeychain[]): this; ignoreLegacyKeychains(): this; class(value: string): this;
  caseInsensitive(value: boolean | null): this; keyClass(value: string): this; loadRefs(value?: boolean): this;
  loadAttributes(value?: boolean): this; loadData(value?: boolean): this; limit(value: number | "all"): this;
  label(value: string): this; trustedOnly(value: boolean | null): this; service(value: string): this;
  subject(value: string): this; account(value: string): this; accessGroup(value: string): this;
  cloudSync(value: string): this; accessGroupToken(): this; publicKeyHash(value: Binary): this;
  serialNumber(value: Binary): this; applicationLabel(value: Binary): this; skipAuthenticatedItems(value?: boolean): this;
  toDictionary(): Record<string, unknown>;
  search(): SearchResult[]; delete(): void;
}
export class ItemAddOptions {
  constructor(value: ItemReference | ItemData);
  static new(value: ItemReference | ItemData): ItemAddOptions;
  setAccountName(value: string): this; setAccessGroup(value: string): this; setComment(value: string): this;
  setDescription(value: string): this; setLabel(value: string): this; setLocation(value: unknown): this;
  setService(value: string): this; add(): void; toDictionary(): Record<string, unknown>;
}
export class ItemUpdateOptions {
  static new(): ItemUpdateOptions;
  setValue(value: ItemReference | ItemData): this; setClass(value: string): this;
  setAccountName(value: string): this; setAccessGroup(value: string): this; setComment(value: string): this;
  setDescription(value: string): this; setLabel(value: string): this; setLocation(value: unknown): this; setService(value: string): this;
  toDictionary(): Record<string, unknown>;
}
export function addItem(options: ItemAddOptions): void;
export function updateItem(search: ItemSearchOptions, update: ItemUpdateOptions): void;
export const add_item: typeof addItem;
export const update_item: typeof updateItem;

export const SecPreferencesDomain: Readonly<Record<string, string>>;
export class KeychainCreateOptions { static new(): KeychainCreateOptions; password(value: string): this; promptUser(value: boolean): this }
export class KeychainSettings { static new(): KeychainSettings; setLockOnSleep(value: boolean): this; setLockInterval(value: number | null): this }
export class KeychainUserInteractionLock implements DisposableNative { readonly handle: number; dispose(): void }
export interface FoundPassword { password: Buffer; item: SecKeychainItem }
export class SecKeychain implements DisposableNative {
  readonly handle: number;
  static default(): SecKeychain; static defaultForDomain(domain: string): SecKeychain; static open(path: string): SecKeychain;
  static create(path: string, options?: KeychainCreateOptions): SecKeychain; static userInteractionAllowed(): boolean;
  static disableUserInteraction(): KeychainUserInteractionLock;
  static findGenericPassword(keychains: SecKeychain[] | null, service: string, account: string): FoundPassword;
  static findInternetPassword(keychains: SecKeychain[] | null, server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): FoundPassword;
  static default_for_domain: typeof SecKeychain.defaultForDomain;
  static user_interaction_allowed: typeof SecKeychain.userInteractionAllowed;
  static disable_user_interaction: typeof SecKeychain.disableUserInteraction;
  static find_generic_password: typeof SecKeychain.findGenericPassword;
  static find_internet_password: typeof SecKeychain.findInternetPassword;
  unlock(password?: string | null): void; setSettings(settings: KeychainSettings): void;
  findGenericPassword(service: string, account: string): FoundPassword;
  findInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): FoundPassword;
  setGenericPassword(service: string, account: string, password: Binary): void;
  addGenericPassword(service: string, account: string, password: Binary): void;
  setInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number, password: Binary): void;
  addInternetPassword(server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number, password: Binary): void;
  dispose(): void;
}
export class SecKeychainItem implements DisposableNative { readonly handle: number; setPassword(password: Binary): void; delete(): void; dispose(): void }
export function findGenericPassword(keychains: SecKeychain[] | null, service: string, account: string): FoundPassword;
export function findInternetPassword(keychains: SecKeychain[] | null, server: string, securityDomain: string | null, account: string, path: string, port: number | null, protocol: number, authenticationType: number): FoundPassword;
export const find_generic_password: typeof findGenericPassword;
export const find_internet_password: typeof findInternetPassword;

export const DigestType: Readonly<Record<string, string>>;
export class DigestBuilder { static new(): DigestBuilder; type(value: string): this; type_(value: string): this; length(value: number): this; hmacKey(value: Binary): this; execute(data: Binary): Buffer }
export const Padding: Readonly<Record<string, string>>;
export const Mode: Readonly<Record<string, string>>;
export class EncryptBuilder { static new(): EncryptBuilder; padding(value: string): this; mode(value: string): this; iv(value: Binary): this; encrypt(key: SecKey, data: Binary): Buffer; decrypt(key: SecKey, data: Binary): Buffer }

export const SignedAttributes: Readonly<Record<string, number>>;
export const CmsCertificateChainMode: Readonly<Record<string, number>>;
export class CmsEncoder implements DisposableNative {
  readonly handle: number; static create(): CmsEncoder; setSignerAlgorithm(value: string): this;
  addSigners(values: SecIdentity[]): this; getSigners(): SecIdentity[]; addRecipients(values: SecCertificate[]): this;
  getRecipients(): SecCertificate[]; setHasDetachedContent(value: boolean): this; getHasDetachedContent(): boolean;
  setEncapsulatedContentTypeOid(value: string): this; getEncapsulatedContentType(): Buffer;
  addSupportingCerts(values: SecCertificate[]): this; getSupportingCerts(): SecCertificate[];
  addSignedAttributes(flags: number): this; setCertificateChainMode(mode: number): this; getCertificateChainMode(): number;
  updateContent(data: Binary): this; getEncodedContent(): Buffer;
  getSignerTimestamp(index: number): number; getSignerTimestampWithPolicy(policy: string | null, index: number): number; dispose(): void;
}
export class CmsDecoder implements DisposableNative {
  readonly handle: number; static create(): CmsDecoder; updateMessage(data: Binary): this; finalizeMessage(): this;
  setDetachedContent(data: Binary): this; getDetachedContent(): Buffer; getNumSigners(): number;
  getSignerStatus(index: number, policies?: SecPolicy[]): { signerStatus: string; trust: SecTrust; certificateVerificationError: string | null };
  getSignerEmailAddress(index: number): string; isContentEncrypted(): boolean; getEncapsulatedContentType(): Buffer;
  getAllCerts(): SecCertificate[]; getContent(): Buffer; getSignerSigningTime(index: number): number;
  getSignerTimestamp(index: number): number; getSignerTimestampWithPolicy(policy: string | null, index: number): number;
  getSignerTimestampCertificates(index: number): SecCertificate[]; dispose(): void;
}
export function cmsEncodeContent(signers: SecIdentity[], recipients: SecCertificate[], contentTypeOid: string | null, detached: boolean, signedAttributes: number, content: Binary): Buffer;
export const cms_encode_content: typeof cmsEncodeContent;
export const CMSEncoder: typeof CmsEncoder;
export const CMSDecoder: typeof CmsDecoder;

export const TrustSettingsDomain: Readonly<Record<string, string>>;
export const TrustSettingsForCertificate: Readonly<Record<"TrustRoot" | "TrustAsRoot" | "Deny" | "Unspecified" | "Invalid", string>>;
export class TrustSettings implements Iterable<SecCertificate> {
  constructor(domain: string); static new(domain: string): TrustSettings; certificates(): SecCertificate[]; iter(): Iterator<SecCertificate>; setTrustSettingsAlways(certificate: SecCertificate): void;
  tlsTrustSettingsForCertificate(certificate: SecCertificate): "TrustRoot" | "TrustAsRoot" | "Deny" | "Unspecified" | "Invalid" | null;
  [Symbol.iterator](): Iterator<SecCertificate>;
}

export const CodeSigningFlags: Readonly<Record<string, number>>;
export class SecRequirement implements DisposableNative { readonly handle: number; static parse(requirement: string): SecRequirement; dispose(): void }
export class GuestAttributes { static new(): GuestAttributes; setPid(pid: number): this; setAuditToken(value: Binary): this; setOther(key: string, value: string): this }
export class SecCode implements DisposableNative { readonly handle: number; static forSelf(flags?: number): SecCode; static for_self: typeof SecCode.forSelf; static copyGuestWithAttributes(host: SecCode | null, attributes: GuestAttributes, flags?: number): SecCode; static copy_guest_with_attributes: typeof SecCode.copyGuestWithAttributes; static copy_guest_with_attribues: typeof SecCode.copyGuestWithAttributes; checkValidity(flags: number, requirement: SecRequirement): void; path(flags?: number): string; dispose(): void }
export class SecStaticCode implements DisposableNative { readonly handle: number; static fromPath(path: string, flags?: number): SecStaticCode; static from_path: typeof SecStaticCode.fromPath; checkValidity(flags: number, requirement: SecRequirement): void; path(flags?: number): string; dispose(): void }

export const AuthorizationFlags: Readonly<Record<string, number>>;
export interface AuthorizationItem { name: string; value?: string; string?: boolean }
export class AuthorizationItemSetBuilder { static new(): AuthorizationItemSetBuilder; addRight(name: string): this; addData(name: string, value: Binary): this; addString(name: string, value: string): this; build(): AuthorizationItem[] }
export class Authorization implements DisposableNative {
  readonly handle: number; static create(rights?: AuthorizationItem[] | null, environment?: AuthorizationItem[] | null, flags?: number): Authorization;
  static new(rights?: AuthorizationItem[] | null, environment?: AuthorizationItem[] | null, flags?: number): Authorization;
  static default(): Authorization; static fromExternalForm(data: Binary): Authorization; static rightExists(name: string): boolean; static getRight(name: string): string;
  static from_external_form: typeof Authorization.fromExternalForm; static right_exists: typeof Authorization.rightExists; static get_right: typeof Authorization.getRight;
  destroyRights(): void; removeRight(name: string): void; setRight(name: string, existingRight: string, description?: string | null, locale?: string | null): void;
  copyInfo(tag?: string | null): string; makeExternalForm(): Buffer;
  executeWithPrivileges(command: string, args?: string[], flags?: number): void;
  executeWithPrivilegesPiped(command: string, args?: string[], flags?: number): Buffer; jobBless(label: string): void; dispose(): void;
}

export const CipherSuite: Readonly<Record<string, number | ((value: number) => number)>>;
export const SslProtocolSide: Readonly<Record<string, string>>;
export const SslConnectionType: Readonly<Record<string, string>>;
export const SslProtocol: Readonly<Record<string, string>>;
export const SslAuthenticate: Readonly<Record<string, string>>;
export const SessionState: Readonly<Record<string, string>>;
export const SslClientCertificateState: Readonly<Record<string, string>>;
export class MidHandshakeSslStream implements DisposableNative {
  readonly handle: number; getRef(): TcpStreamInfo; getMut(): TcpStreamInfo; context(): SslContext; contextMut(): SslContext;
  error(): SecurityFrameworkError; serverAuthCompleted(): boolean; clientCertRequested(): boolean; wouldBlock(): boolean;
  clientHelloReceived(): boolean; handshake(): SslStream; dispose(): void;
}
export class MidHandshakeClientBuilder implements DisposableNative {
  readonly handle: number; getRef(): TcpStreamInfo; getMut(): TcpStreamInfo; error(): SecurityFrameworkError; handshake(): SslStream; dispose(): void;
}
export class SslContext implements DisposableNative {
  readonly handle: number; static create(side: string, connectionType?: string): SslContext;
  static new(side: string, connectionType?: string): SslContext;
  setPeerDomainName(value: string): this; peerDomainName(): string; setCertificate(identity: SecIdentity, certificates?: SecCertificate[]): this;
  setPeerId(data: Binary): this; peerId(): Buffer | null; supportedCiphers(): number[]; enabledCiphers(): number[];
  setEnabledCiphers(ciphers: number[]): this; negotiatedCipher(): number; setClientSideAuthenticate(value: string): this;
  clientCertificateState(): "none" | "rejected" | "requested" | "sent"; peerTrust(): SecTrust | null; peerTrust2(): SecTrust | null;
  state(): "aborted" | "closed" | "connected" | "handshake" | "idle"; negotiatedProtocolVersion(): string;
  protocolVersionMax(): string; setProtocolVersionMax(value: string): this; protocolVersionMin(): string; setProtocolVersionMin(value: string): this;
  alpnProtocols(): string[]; setAlpnProtocols(values: string[]): this; setSessionTicketsEnabled(value: boolean): this;
  bufferedReadSize(): number; getOption(name: string): boolean; setOption(name: string, value: boolean): this;
  breakOnServerAuth(): boolean; setBreakOnServerAuth(value: boolean): this; breakOnCertRequested(): boolean; setBreakOnCertRequested(value: boolean): this;
  breakOnClientAuth(): boolean; setBreakOnClientAuth(value: boolean): this; falseStart(): boolean; setFalseStart(value: boolean): this;
  sendOneByteRecord(): boolean; setSendOneByteRecord(value: boolean): this; allowServerIdentityChange(): boolean; setAllowServerIdentityChange(value: boolean): this;
  fallback(): boolean; setFallback(value: boolean): this; breakOnClientHello(): boolean; setBreakOnClientHello(value: boolean): this;
  diffieHellmanParams(): Buffer | null; setDiffieHellmanParams(value: Binary): this; certificateAuthorities(): SecCertificate[] | null;
  setCertificateAuthorities(values: SecCertificate[]): this; addCertificateAuthorities(values: SecCertificate[]): this;
  connect(host: string, port: number): SslStream; handshake(host: string, port: number): SslStream; dispose(): void;
}
export interface TcpStreamInfo { localAddress: string; peerAddress: string }
export class SslStream implements DisposableNative { readonly handle: number; read(length: number): Buffer; write(data: Binary): number; flush(): void; close(): void; context(): SslContext; contextMut(): SslContext; getRef(): TcpStreamInfo; getMut(): TcpStreamInfo; dispose(): void }
export class ClientBuilder {
  static new(): ClientBuilder;
  anchorCertificates(values: SecCertificate[]): this; addAnchorCertificate(value: SecCertificate): this; trustAnchorCertificatesOnly(value: boolean): this;
  dangerAcceptInvalidCerts(value: boolean): this; useSni(value: boolean): this; dangerAcceptInvalidHostnames(value: boolean): this;
  whitelistCiphers(value: number[]): this; blacklistCiphers(value: number[]): this; identity(value: SecIdentity, chain?: SecCertificate[]): this;
  protocolMin(value: string): this; protocolMax(value: string): this; alpnProtocols(value: string[]): this;
  enableSessionTickets(value: boolean): this; connect(domain: string, host: string, port: number): SslStream; handshake(domain: string, host: string, port: number): SslStream;
}
export class ServerBuilder { constructor(identity: SecIdentity, certificates?: SecCertificate[]); static new(identity: SecIdentity, certificates?: SecCertificate[]): ServerBuilder; static fromPkcs12(data: Binary, passphrase: string): ServerBuilder; static from_pkcs12: typeof ServerBuilder.fromPkcs12; newSslContext(): SslContext; handshake(host: string, port: number): SslStream }

// Rust-spelled aliases mirror every multiword public method on the JavaScript classes.
export interface SecCertificate { to_der: SecCertificate["toDer"]; add_to_keychain: SecCertificate["addToKeychain"]; subject_summary: SecCertificate["subjectSummary"]; email_addresses: SecCertificate["emailAddresses"]; serial_number_bytes: SecCertificate["serialNumberBytes"]; public_key_info_der: SecCertificate["publicKeyInfoDer"]; public_key: SecCertificate["publicKey"]; common_name: SecCertificate["commonName"]; signature_algorithm_property: SecCertificate["signatureAlgorithmProperty"] }
export interface SecIdentity { private_key: SecIdentity["privateKey"] }
export interface GenerateKeyOptions { set_key_type: GenerateKeyOptions["setKeyType"]; set_size_in_bits: GenerateKeyOptions["setSizeInBits"]; set_label: GenerateKeyOptions["setLabel"]; set_token: GenerateKeyOptions["setToken"]; set_location: GenerateKeyOptions["setLocation"]; set_access_control: GenerateKeyOptions["setAccessControl"]; set_synchronizable: GenerateKeyOptions["setSynchronizable"]; to_dictionary: GenerateKeyOptions["toDictionary"] }
export interface SecKey { application_label: SecKey["applicationLabel"]; external_representation: SecKey["externalRepresentation"]; public_key: SecKey["publicKey"]; encrypt_data: SecKey["encryptData"]; decrypt_data: SecKey["decryptData"]; create_signature: SecKey["createSignature"]; verify_signature: SecKey["verifySignature"]; key_exchange: SecKey["keyExchange"] }
export interface SecTrust { set_trust_verify_date: SecTrust["setTrustVerifyDate"]; set_anchor_certificates: SecTrust["setAnchorCertificates"]; set_trust_anchor_certificates_only: SecTrust["setTrustAnchorCertificatesOnly"]; set_policy: SecTrust["setPolicy"]; set_options: SecTrust["setOptions"]; get_network_fetch_allowed: SecTrust["getNetworkFetchAllowed"]; set_network_fetch_allowed: SecTrust["setNetworkFetchAllowed"]; set_trust_ocsp_response: SecTrust["setTrustOcspResponse"]; set_signed_certificate_timestamps: SecTrust["setSignedCertificateTimestamps"]; copy_public_key: SecTrust["copyPublicKey"]; evaluate_with_error: SecTrust["evaluateWithError"]; certificate_count: SecTrust["certificateCount"]; certificate_at_index: SecTrust["certificateAtIndex"] }
export interface SecRandom { copy_bytes: SecRandom["copyBytes"] }
export interface PasswordOptions { set_access_control_options: PasswordOptions["setAccessControlOptions"]; set_access_control: PasswordOptions["setAccessControl"]; set_access_group: PasswordOptions["setAccessGroup"]; set_access_synchronized: PasswordOptions["setAccessSynchronized"]; set_comment: PasswordOptions["setComment"]; set_description: PasswordOptions["setDescription"]; set_label: PasswordOptions["setLabel"]; use_protected_keychain: PasswordOptions["useProtectedKeychain"]; to_dictionary: PasswordOptions["toDictionary"] }
export interface ImportOptions { passphrase_bytes: ImportOptions["passphraseBytes"]; secure_passphrase: ImportOptions["securePassphrase"]; no_access_control: ImportOptions["noAccessControl"]; alert_title: ImportOptions["alertTitle"]; alert_prompt: ImportOptions["alertPrompt"] }
export interface ItemSearchOptions { ignore_legacy_keychains: ItemSearchOptions["ignoreLegacyKeychains"]; case_insensitive: ItemSearchOptions["caseInsensitive"]; key_class: ItemSearchOptions["keyClass"]; load_refs: ItemSearchOptions["loadRefs"]; load_attributes: ItemSearchOptions["loadAttributes"]; load_data: ItemSearchOptions["loadData"]; trusted_only: ItemSearchOptions["trustedOnly"]; access_group: ItemSearchOptions["accessGroup"]; cloud_sync: ItemSearchOptions["cloudSync"]; access_group_token: ItemSearchOptions["accessGroupToken"]; public_key_hash: ItemSearchOptions["publicKeyHash"]; pub_key_hash: ItemSearchOptions["publicKeyHash"]; serial_number: ItemSearchOptions["serialNumber"]; application_label: ItemSearchOptions["applicationLabel"]; skip_authenticated_items: ItemSearchOptions["skipAuthenticatedItems"]; to_dictionary: ItemSearchOptions["toDictionary"] }
export interface ItemAddOptions { set_account_name: ItemAddOptions["setAccountName"]; set_access_group: ItemAddOptions["setAccessGroup"]; set_comment: ItemAddOptions["setComment"]; set_description: ItemAddOptions["setDescription"]; set_label: ItemAddOptions["setLabel"]; set_location: ItemAddOptions["setLocation"]; set_service: ItemAddOptions["setService"]; to_dictionary: ItemAddOptions["toDictionary"] }
export interface ItemUpdateOptions { set_value: ItemUpdateOptions["setValue"]; set_class: ItemUpdateOptions["setClass"]; set_account_name: ItemUpdateOptions["setAccountName"]; set_access_group: ItemUpdateOptions["setAccessGroup"]; set_comment: ItemUpdateOptions["setComment"]; set_description: ItemUpdateOptions["setDescription"]; set_label: ItemUpdateOptions["setLabel"]; set_location: ItemUpdateOptions["setLocation"]; set_service: ItemUpdateOptions["setService"]; to_dictionary: ItemUpdateOptions["toDictionary"] }
export interface KeychainCreateOptions { prompt_user: KeychainCreateOptions["promptUser"] }
export interface KeychainSettings { set_lock_on_sleep: KeychainSettings["setLockOnSleep"]; set_lock_interval: KeychainSettings["setLockInterval"] }
export interface SecKeychain { set_settings: SecKeychain["setSettings"]; find_generic_password: SecKeychain["findGenericPassword"]; find_internet_password: SecKeychain["findInternetPassword"]; set_generic_password: SecKeychain["setGenericPassword"]; add_generic_password: SecKeychain["addGenericPassword"]; set_internet_password: SecKeychain["setInternetPassword"]; add_internet_password: SecKeychain["addInternetPassword"] }
export interface SecKeychainItem { set_password: SecKeychainItem["setPassword"] }
export interface DigestBuilder { hmac_key: DigestBuilder["hmacKey"] }
export interface CmsEncoder { set_signer_algorithm: CmsEncoder["setSignerAlgorithm"]; add_signers: CmsEncoder["addSigners"]; get_signers: CmsEncoder["getSigners"]; add_recipients: CmsEncoder["addRecipients"]; get_recipients: CmsEncoder["getRecipients"]; set_has_detached_content: CmsEncoder["setHasDetachedContent"]; get_has_detached_content: CmsEncoder["getHasDetachedContent"]; set_encapsulated_content_type_oid: CmsEncoder["setEncapsulatedContentTypeOid"]; get_encapsulated_content_type: CmsEncoder["getEncapsulatedContentType"]; add_supporting_certs: CmsEncoder["addSupportingCerts"]; get_supporting_certs: CmsEncoder["getSupportingCerts"]; add_signed_attributes: CmsEncoder["addSignedAttributes"]; set_certificate_chain_mode: CmsEncoder["setCertificateChainMode"]; get_certificate_chain_mode: CmsEncoder["getCertificateChainMode"]; update_content: CmsEncoder["updateContent"]; get_encoded_content: CmsEncoder["getEncodedContent"]; get_signer_timestamp: CmsEncoder["getSignerTimestamp"]; get_signer_timestamp_with_policy: CmsEncoder["getSignerTimestampWithPolicy"] }
export interface CmsDecoder { update_message: CmsDecoder["updateMessage"]; finalize_message: CmsDecoder["finalizeMessage"]; set_detached_content: CmsDecoder["setDetachedContent"]; get_detached_content: CmsDecoder["getDetachedContent"]; get_num_signers: CmsDecoder["getNumSigners"]; get_signer_status: CmsDecoder["getSignerStatus"]; get_signer_email_address: CmsDecoder["getSignerEmailAddress"]; is_content_encrypted: CmsDecoder["isContentEncrypted"]; get_encapsulated_content_type: CmsDecoder["getEncapsulatedContentType"]; get_all_certs: CmsDecoder["getAllCerts"]; get_content: CmsDecoder["getContent"]; get_signer_signing_time: CmsDecoder["getSignerSigningTime"]; get_signer_timestamp: CmsDecoder["getSignerTimestamp"]; get_signer_timestamp_with_policy: CmsDecoder["getSignerTimestampWithPolicy"]; get_signer_timestamp_certificates: CmsDecoder["getSignerTimestampCertificates"] }
export interface TrustSettings { set_trust_settings_always: TrustSettings["setTrustSettingsAlways"]; tls_trust_settings_for_certificate: TrustSettings["tlsTrustSettingsForCertificate"] }
export interface GuestAttributes { set_pid: GuestAttributes["setPid"]; set_audit_token: GuestAttributes["setAuditToken"]; set_other: GuestAttributes["setOther"] }
export interface SecCode { check_validity: SecCode["checkValidity"] }
export interface SecStaticCode { check_validity: SecStaticCode["checkValidity"] }
export interface AuthorizationItemSetBuilder { add_right: AuthorizationItemSetBuilder["addRight"]; add_data: AuthorizationItemSetBuilder["addData"]; add_string: AuthorizationItemSetBuilder["addString"] }
export interface Authorization { destroy_rights: Authorization["destroyRights"]; remove_right: Authorization["removeRight"]; set_right: Authorization["setRight"]; copy_info: Authorization["copyInfo"]; make_external_form: Authorization["makeExternalForm"]; execute_with_privileges: Authorization["executeWithPrivileges"]; execute_with_privileges_piped: Authorization["executeWithPrivilegesPiped"]; job_bless: Authorization["jobBless"] }
export interface MidHandshakeSslStream { get_ref: MidHandshakeSslStream["getRef"]; get_mut: MidHandshakeSslStream["getMut"]; context_mut: MidHandshakeSslStream["contextMut"]; server_auth_completed: MidHandshakeSslStream["serverAuthCompleted"]; client_cert_requested: MidHandshakeSslStream["clientCertRequested"]; would_block: MidHandshakeSslStream["wouldBlock"]; client_hello_received: MidHandshakeSslStream["clientHelloReceived"] }
export interface MidHandshakeClientBuilder { get_ref: MidHandshakeClientBuilder["getRef"]; get_mut: MidHandshakeClientBuilder["getMut"] }
export interface SslContext { set_peer_domain_name: SslContext["setPeerDomainName"]; peer_domain_name: SslContext["peerDomainName"]; set_certificate: SslContext["setCertificate"]; set_peer_id: SslContext["setPeerId"]; peer_id: SslContext["peerId"]; supported_ciphers: SslContext["supportedCiphers"]; enabled_ciphers: SslContext["enabledCiphers"]; set_enabled_ciphers: SslContext["setEnabledCiphers"]; negotiated_cipher: SslContext["negotiatedCipher"]; set_client_side_authenticate: SslContext["setClientSideAuthenticate"]; client_certificate_state: SslContext["clientCertificateState"]; peer_trust: SslContext["peerTrust"]; peer_trust2: SslContext["peerTrust2"]; negotiated_protocol_version: SslContext["negotiatedProtocolVersion"]; protocol_version_max: SslContext["protocolVersionMax"]; set_protocol_version_max: SslContext["setProtocolVersionMax"]; protocol_version_min: SslContext["protocolVersionMin"]; set_protocol_version_min: SslContext["setProtocolVersionMin"]; alpn_protocols: SslContext["alpnProtocols"]; set_alpn_protocols: SslContext["setAlpnProtocols"]; set_session_tickets_enabled: SslContext["setSessionTicketsEnabled"]; buffered_read_size: SslContext["bufferedReadSize"]; get_option: SslContext["getOption"]; set_option: SslContext["setOption"]; diffie_hellman_params: SslContext["diffieHellmanParams"]; set_diffie_hellman_params: SslContext["setDiffieHellmanParams"]; certificate_authorities: SslContext["certificateAuthorities"]; set_certificate_authorities: SslContext["setCertificateAuthorities"]; add_certificate_authorities: SslContext["addCertificateAuthorities"]; break_on_server_auth: SslContext["breakOnServerAuth"]; set_break_on_server_auth: SslContext["setBreakOnServerAuth"]; break_on_cert_requested: SslContext["breakOnCertRequested"]; set_break_on_cert_requested: SslContext["setBreakOnCertRequested"]; break_on_client_auth: SslContext["breakOnClientAuth"]; set_break_on_client_auth: SslContext["setBreakOnClientAuth"]; false_start: SslContext["falseStart"]; set_false_start: SslContext["setFalseStart"]; send_one_byte_record: SslContext["sendOneByteRecord"]; set_send_one_byte_record: SslContext["setSendOneByteRecord"]; allow_server_identity_change: SslContext["allowServerIdentityChange"]; set_allow_server_identity_change: SslContext["setAllowServerIdentityChange"]; set_fallback: SslContext["setFallback"]; break_on_client_hello: SslContext["breakOnClientHello"]; set_break_on_client_hello: SslContext["setBreakOnClientHello"] }
export interface SslStream { context_mut: SslStream["contextMut"]; get_ref: SslStream["getRef"]; get_mut: SslStream["getMut"] }
export interface ClientBuilder { anchor_certificates: ClientBuilder["anchorCertificates"]; add_anchor_certificate: ClientBuilder["addAnchorCertificate"]; trust_anchor_certificates_only: ClientBuilder["trustAnchorCertificatesOnly"]; danger_accept_invalid_certs: ClientBuilder["dangerAcceptInvalidCerts"]; use_sni: ClientBuilder["useSni"]; danger_accept_invalid_hostnames: ClientBuilder["dangerAcceptInvalidHostnames"]; whitelist_ciphers: ClientBuilder["whitelistCiphers"]; blacklist_ciphers: ClientBuilder["blacklistCiphers"]; protocol_min: ClientBuilder["protocolMin"]; protocol_max: ClientBuilder["protocolMax"]; alpn_protocols: ClientBuilder["alpnProtocols"]; enable_session_tickets: ClientBuilder["enableSessionTickets"] }
export interface ServerBuilder { new_ssl_context: ServerBuilder["newSslContext"] }

export const passwords: Readonly<Record<string, unknown>>;
export const cms: Readonly<Record<string, unknown>>;
export const access_control: Readonly<Record<string, unknown>>;
export const authorization: Readonly<Record<string, unknown>>;
export const base: Readonly<Record<string, unknown>>;
export const certificate: Readonly<Record<string, unknown>>;
export const cipher_suite: Readonly<Record<string, unknown>>;
export const identity: Readonly<Record<string, unknown>>;
export const import_export: Readonly<Record<string, unknown>>;
export const item: Readonly<Record<string, unknown>>;
export const key: Readonly<Record<string, unknown>>;
export const policy: Readonly<Record<string, unknown>>;
export const random: Readonly<Record<string, unknown>>;
export const secure_transport: Readonly<Record<string, unknown>>;
export const trust: Readonly<Record<string, unknown>>;
export const trust_settings: Readonly<Record<string, unknown>>;
export const os: Readonly<Record<string, unknown>>;
