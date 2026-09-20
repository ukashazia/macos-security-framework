#![cfg(target_os = "macos")]
#![allow(deprecated)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_char;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use napi_derive::napi;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::authorization::{
    Authorization, AuthorizationItemSetBuilder, Flags as AuthorizationFlags, RightDefinition,
};
use security_framework::certificate::SecCertificate;
use security_framework::cipher_suite::CipherSuite;
use security_framework::cms::{CMSDecoder, CMSEncoder, SignedAttributes, cms_encode_content};
use security_framework::identity::SecIdentity;
use security_framework::import_export::Pkcs12ImportOptions;
use security_framework::item::{
    AddRef, CloudSync, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions,
    ItemUpdateOptions, ItemUpdateValue, KeyClass, Limit, Location, Reference, SearchResult,
    update_item,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::os::macos::certificate::{PropertyType, SecCertificateExt};
use security_framework::os::macos::certificate_oids::CertificateOid;
use security_framework::os::macos::code_signing::{
    Flags as CodeSigningFlags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use security_framework::os::macos::digest_transform::{Builder as DigestBuilder, DigestType};
use security_framework::os::macos::encrypt_transform::{Builder as EncryptBuilder, Mode, Padding};
use security_framework::os::macos::identity::SecIdentityExt;
use security_framework::os::macos::import_export::{ImportOptions, SecItems};
use security_framework::os::macos::key::SecKeyExt;
use security_framework::os::macos::keychain::{
    CreateOptions, KeychainSettings, KeychainUserInteractionLock, SecKeychain,
};
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework::os::macos::passwords::{find_generic_password, find_internet_password};
use security_framework::os::macos::secure_transport::{MidHandshakeSslStreamExt, SslContextExt};
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password,
    delete_generic_password_options, delete_internet_password, generic_password,
    get_generic_password, get_internet_password, set_generic_password,
    set_generic_password_options, set_internet_password,
};
use security_framework::policy::{RevocationPolicy, SecPolicy};
use security_framework::random::SecRandom;
use security_framework::secure_transport::{
    ClientBuilder, ClientHandshakeError, HandshakeError, MidHandshakeClientBuilder,
    MidHandshakeSslStream, ServerBuilder, SessionState, SslAuthenticate, SslClientCertificateState,
    SslConnectionType, SslContext, SslProtocol, SslProtocolSide, SslStream,
};
use security_framework::trust::{SecTrust, TrustOptions};
use security_framework::trust_settings::{Domain as TrustSettingsDomain, TrustSettings};
use security_framework_sys::authorization::AuthorizationExternalForm;
use security_framework_sys::cms::{CMSCertificateChainMode, CMSSignerStatus};
use security_framework_sys::keychain::SecPreferencesDomain;
use security_framework_sys::keychain::{SecAuthenticationType, SecProtocolType};
use serde_json::{Value, json};

type R<T> = Result<T, String>;

enum NativeObject {
    AccessControl(SecAccessControl),
    Authorization(Authorization),
    Certificate(SecCertificate),
    CmsDecoder(CMSDecoder),
    CmsEncoder(CMSEncoder),
    Identity(SecIdentity),
    Key(SecKey),
    Keychain(SecKeychain),
    KeychainItem(SecKeychainItem),
    KeychainUserInteractionLock(KeychainUserInteractionLock),
    Policy(SecPolicy),
    Requirement(SecRequirement),
    Code(SecCode),
    StaticCode(SecStaticCode),
    MidHandshakeClientBuilder(MidHandshakeClientBuilder<TcpStream>),
    MidHandshakeSslStream(MidHandshakeSslStream<TcpStream>),
    SslContext(SslContext),
    SslStream(SslStream<TcpStream>),
    Trust(SecTrust),
}

struct Registry {
    next: u64,
    objects: HashMap<u64, NativeObject>,
}

impl Registry {
    fn insert(&mut self, object: NativeObject) -> u64 {
        let id = self.next;
        self.next += 1;
        self.objects.insert(id, object);
        id
    }
}

thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry { next: 1, objects: HashMap::new() });
}

fn insert(object: NativeObject) -> Value {
    json!(REGISTRY.with(|registry| registry.borrow_mut().insert(object)))
}

macro_rules! object_getter {
    ($name:ident, $variant:ident, $ty:ty) => {
        fn $name(id: u64) -> R<$ty> {
            REGISTRY.with(|registry| match registry.borrow().objects.get(&id) {
                Some(NativeObject::$variant(value)) => Ok(value.clone()),
                Some(_) => Err(format!("handle {id} has the wrong native type")),
                None => Err(format!("unknown or disposed native handle {id}")),
            })
        }
    };
}

object_getter!(access_control, AccessControl, SecAccessControl);
object_getter!(certificate, Certificate, SecCertificate);
object_getter!(cms_decoder, CmsDecoder, CMSDecoder);
object_getter!(cms_encoder, CmsEncoder, CMSEncoder);
object_getter!(identity, Identity, SecIdentity);
object_getter!(key, Key, SecKey);
object_getter!(keychain, Keychain, SecKeychain);
object_getter!(keychain_item, KeychainItem, SecKeychainItem);
object_getter!(policy, Policy, SecPolicy);
object_getter!(requirement, Requirement, SecRequirement);
object_getter!(code, Code, SecCode);
object_getter!(static_code, StaticCode, SecStaticCode);
object_getter!(ssl_context, SslContext, SslContext);
object_getter!(trust, Trust, SecTrust);

fn with_ssl_stream<T>(id: u64, run: impl FnOnce(&mut SslStream<TcpStream>) -> R<T>) -> R<T> {
    REGISTRY.with(
        |registry| match registry.borrow_mut().objects.get_mut(&id) {
            Some(NativeObject::SslStream(value)) => run(value),
            Some(_) => Err(format!("handle {id} has the wrong native type")),
            None => Err(format!("unknown or disposed native handle {id}")),
        },
    )
}

fn with_mid_handshake_stream<T>(
    id: u64,
    run: impl FnOnce(&mut MidHandshakeSslStream<TcpStream>) -> R<T>,
) -> R<T> {
    REGISTRY.with(
        |registry| match registry.borrow_mut().objects.get_mut(&id) {
            Some(NativeObject::MidHandshakeSslStream(value)) => run(value),
            Some(_) => Err(format!("handle {id} has the wrong native type")),
            None => Err(format!("unknown or disposed native handle {id}")),
        },
    )
}

fn with_mid_handshake_client<T>(
    id: u64,
    run: impl FnOnce(&mut MidHandshakeClientBuilder<TcpStream>) -> R<T>,
) -> R<T> {
    REGISTRY.with(
        |registry| match registry.borrow_mut().objects.get_mut(&id) {
            Some(NativeObject::MidHandshakeClientBuilder(value)) => run(value),
            Some(_) => Err(format!("handle {id} has the wrong native type")),
            None => Err(format!("unknown or disposed native handle {id}")),
        },
    )
}

fn take_object(id: u64) -> R<NativeObject> {
    REGISTRY
        .with(|registry| registry.borrow_mut().objects.remove(&id))
        .ok_or_else(|| format!("unknown or disposed native handle {id}"))
}

fn with_authorization<T>(id: u64, run: impl FnOnce(&Authorization) -> R<T>) -> R<T> {
    REGISTRY.with(|registry| match registry.borrow().objects.get(&id) {
        Some(NativeObject::Authorization(value)) => run(value),
        Some(_) => Err(format!("handle {id} has the wrong native type")),
        None => Err(format!("unknown or disposed native handle {id}")),
    })
}

fn arg<'a>(args: &'a Value, name: &str) -> R<&'a Value> {
    args.get(name)
        .ok_or_else(|| format!("missing argument `{name}`"))
}

fn string<'a>(args: &'a Value, name: &str) -> R<&'a str> {
    arg(args, name)?
        .as_str()
        .ok_or_else(|| format!("`{name}` must be a string"))
}

fn optional_string<'a>(args: &'a Value, name: &str) -> R<Option<&'a str>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("`{name}` must be a string or null")),
    }
}

fn boolean(args: &Value, name: &str) -> R<bool> {
    arg(args, name)?
        .as_bool()
        .ok_or_else(|| format!("`{name}` must be a boolean"))
}

fn optional_bool(args: &Value, name: &str) -> R<Option<bool>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("`{name}` must be a boolean or null")),
    }
}

fn number(args: &Value, name: &str) -> R<u64> {
    arg(args, name)?
        .as_u64()
        .ok_or_else(|| format!("`{name}` must be a non-negative integer"))
}

fn handle(args: &Value, name: &str) -> R<u64> {
    number(args, name)
}

fn handles(args: &Value, name: &str) -> R<Vec<u64>> {
    arg(args, name)?
        .as_array()
        .ok_or_else(|| format!("`{name}` must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("`{name}` must contain handles"))
        })
        .collect()
}

fn decode_hex(value: &str) -> R<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err("hex data must have an even number of characters".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid hex data".to_string())?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid hex data".to_string())
        })
        .collect()
}

fn bytes(args: &Value, name: &str) -> R<Vec<u8>> {
    decode_hex(string(args, name)?)
}

fn optional_bytes(args: &Value, name: &str) -> R<Option<Vec<u8>>> {
    optional_string(args, name)?.map(decode_hex).transpose()
}

fn hex(value: impl AsRef<[u8]>) -> Value {
    Value::String(
        value
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

fn protection(value: Option<&str>) -> R<Option<ProtectionMode>> {
    value
        .map(|value| match value {
            "accessibleWhenPasscodeSetThisDeviceOnly" => {
                Ok(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly)
            }
            "accessibleWhenUnlockedThisDeviceOnly" => {
                Ok(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly)
            }
            "accessibleWhenUnlocked" => Ok(ProtectionMode::AccessibleWhenUnlocked),
            "accessibleAfterFirstUnlockThisDeviceOnly" => {
                Ok(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly)
            }
            "accessibleAfterFirstUnlock" => Ok(ProtectionMode::AccessibleAfterFirstUnlock),
            _ => Err(format!("unknown protection mode `{value}`")),
        })
        .transpose()
}

fn key_type(value: &str) -> R<KeyType> {
    match value {
        "rsa" => Ok(KeyType::rsa()),
        "dsa" => Ok(KeyType::dsa()),
        "aes" => Ok(KeyType::aes()),
        "des" => Ok(KeyType::des()),
        "tripleDes" => Ok(KeyType::triple_des()),
        "rc4" => Ok(KeyType::rc4()),
        "cast" => Ok(KeyType::cast()),
        "ec" => Ok(KeyType::ec()),
        "ecSecPrimeRandom" => Ok(KeyType::ec_sec_prime_random()),
        _ => Err(format!("unknown key type `{value}`")),
    }
}

fn algorithm(value: &str) -> R<Algorithm> {
    macro_rules! algorithms {
        ($($name:ident),+ $(,)?) => { match value { $(stringify!($name) => Ok(Algorithm::$name),)+ _ => Err(format!("unknown key algorithm `{value}`")) } };
    }
    algorithms!(
        ECIESEncryptionStandardX963SHA1AESGCM,
        ECIESEncryptionStandardX963SHA224AESGCM,
        ECIESEncryptionStandardX963SHA256AESGCM,
        ECIESEncryptionStandardX963SHA384AESGCM,
        ECIESEncryptionStandardX963SHA512AESGCM,
        ECIESEncryptionStandardVariableIVX963SHA224AESGCM,
        ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
        ECIESEncryptionStandardVariableIVX963SHA384AESGCM,
        ECIESEncryptionStandardVariableIVX963SHA512AESGCM,
        ECIESEncryptionCofactorVariableIVX963SHA224AESGCM,
        ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        ECIESEncryptionCofactorVariableIVX963SHA384AESGCM,
        ECIESEncryptionCofactorVariableIVX963SHA512AESGCM,
        ECIESEncryptionCofactorX963SHA1AESGCM,
        ECIESEncryptionCofactorX963SHA224AESGCM,
        ECIESEncryptionCofactorX963SHA256AESGCM,
        ECIESEncryptionCofactorX963SHA384AESGCM,
        ECIESEncryptionCofactorX963SHA512AESGCM,
        ECDSASignatureRFC4754,
        ECDSASignatureDigestX962,
        ECDSASignatureDigestX962SHA1,
        ECDSASignatureDigestX962SHA224,
        ECDSASignatureDigestX962SHA256,
        ECDSASignatureDigestX962SHA384,
        ECDSASignatureDigestX962SHA512,
        ECDSASignatureMessageX962SHA1,
        ECDSASignatureMessageX962SHA224,
        ECDSASignatureMessageX962SHA256,
        ECDSASignatureMessageX962SHA384,
        ECDSASignatureMessageX962SHA512,
        ECDHKeyExchangeCofactor,
        ECDHKeyExchangeStandard,
        ECDHKeyExchangeCofactorX963SHA1,
        ECDHKeyExchangeStandardX963SHA1,
        ECDHKeyExchangeCofactorX963SHA224,
        ECDHKeyExchangeCofactorX963SHA256,
        ECDHKeyExchangeCofactorX963SHA384,
        ECDHKeyExchangeCofactorX963SHA512,
        ECDHKeyExchangeStandardX963SHA224,
        ECDHKeyExchangeStandardX963SHA256,
        ECDHKeyExchangeStandardX963SHA384,
        ECDHKeyExchangeStandardX963SHA512,
        RSAEncryptionRaw,
        RSAEncryptionPKCS1,
        RSAEncryptionOAEPSHA1,
        RSAEncryptionOAEPSHA224,
        RSAEncryptionOAEPSHA256,
        RSAEncryptionOAEPSHA384,
        RSAEncryptionOAEPSHA512,
        RSAEncryptionOAEPSHA1AESGCM,
        RSAEncryptionOAEPSHA224AESGCM,
        RSAEncryptionOAEPSHA256AESGCM,
        RSAEncryptionOAEPSHA384AESGCM,
        RSAEncryptionOAEPSHA512AESGCM,
        RSASignatureRaw,
        RSASignatureDigestPKCS1v15Raw,
        RSASignatureDigestPKCS1v15SHA1,
        RSASignatureDigestPKCS1v15SHA224,
        RSASignatureDigestPKCS1v15SHA256,
        RSASignatureDigestPKCS1v15SHA384,
        RSASignatureDigestPKCS1v15SHA512,
        RSASignatureMessagePKCS1v15SHA1,
        RSASignatureMessagePKCS1v15SHA224,
        RSASignatureMessagePKCS1v15SHA256,
        RSASignatureMessagePKCS1v15SHA384,
        RSASignatureMessagePKCS1v15SHA512,
        RSASignatureDigestPSSSHA1,
        RSASignatureDigestPSSSHA224,
        RSASignatureDigestPSSSHA256,
        RSASignatureDigestPSSSHA384,
        RSASignatureDigestPSSSHA512,
        RSASignatureMessagePSSSHA1,
        RSASignatureMessagePSSSHA224,
        RSASignatureMessagePSSSHA256,
        RSASignatureMessagePSSSHA384,
        RSASignatureMessagePSSSHA512
    )
}

fn protocol(value: u64) -> R<SecProtocolType> {
    macro_rules! variants {
        ($($name:ident),+ $(,)?) => { $(if value == SecProtocolType::$name as u64 { return Ok(SecProtocolType::$name); })+ };
    }
    variants!(
        FTP, FTPAccount, HTTP, IRC, NNTP, POP3, SMTP, SOCKS, IMAP, LDAP, AppleTalk, AFP, Telnet,
        SSH, FTPS, HTTPS, HTTPProxy, HTTPSProxy, FTPProxy, CIFS, SMB, RTSP, RTSPProxy, DAAP, EPPC,
        IPP, NNTPS, LDAPS, TelnetS, IMAPS, IRCS, POP3S, CVSpserver, SVN, Any
    );
    Err(format!(
        "unknown Security.framework protocol value `{value}`"
    ))
}

fn authentication(value: u64) -> R<SecAuthenticationType> {
    macro_rules! variants {
        ($($name:ident),+ $(,)?) => { $(if value == SecAuthenticationType::$name as u64 { return Ok(SecAuthenticationType::$name); })+ };
    }
    variants!(
        NTLM, MSN, DPA, RPA, HTTPBasic, HTTPDigest, HTMLForm, Default, Any
    );
    Err(format!(
        "unknown Security.framework authentication value `{value}`"
    ))
}

fn build_password_options(args: &Value) -> R<PasswordOptions> {
    let kind = string(args, "kind")?;
    let mut options = if kind == "generic" {
        PasswordOptions::new_generic_password(string(args, "service")?, string(args, "account")?)
    } else if kind == "internet" {
        PasswordOptions::new_internet_password(
            string(args, "server")?,
            optional_string(args, "securityDomain")?,
            string(args, "account")?,
            string(args, "path")?,
            args.get("port")
                .and_then(Value::as_u64)
                .map(|value| value as u16),
            protocol(number(args, "protocol")?)?,
            authentication(number(args, "authenticationType")?)?,
        )
    } else {
        return Err(format!("unknown password option kind `{kind}`"));
    };
    if let Some(flags) = args.get("accessControlOptions").and_then(Value::as_u64) {
        options.set_access_control_options(AccessControlOptions::from_bits_retain(flags as usize));
    }
    if let Some(id) = args.get("accessControl").and_then(Value::as_u64) {
        options.set_access_control(access_control(id)?);
    }
    if let Some(group) = args.get("accessGroup").and_then(Value::as_str) {
        options.set_access_group(group);
    }
    if let Some(sync) = args.get("synchronized") {
        options.set_access_synchronized(if sync.is_null() { None } else { sync.as_bool() });
    }
    if let Some(value) = args.get("comment").and_then(Value::as_str) {
        options.set_comment(value);
    }
    if let Some(value) = args.get("description").and_then(Value::as_str) {
        options.set_description(value);
    }
    if let Some(value) = args.get("label").and_then(Value::as_str) {
        options.set_label(value);
    }
    if args
        .get("protectedKeychain")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        options.use_protected_keychain();
    }
    Ok(options)
}

fn generate_key_options(args: &Value) -> R<GenerateKeyOptions> {
    let mut options = GenerateKeyOptions::default();
    if let Some(value) = args.get("keyType").and_then(Value::as_str) {
        options.set_key_type(key_type(value)?);
    }
    if let Some(value) = args.get("sizeInBits").and_then(Value::as_u64) {
        options.set_size_in_bits(value as u32);
    }
    if let Some(value) = args.get("label").and_then(Value::as_str) {
        options.set_label(value);
    }
    if let Some(value) = args.get("token").and_then(Value::as_str) {
        options.set_token(match value {
            "software" => Token::Software,
            "secureEnclave" => Token::SecureEnclave,
            _ => return Err(format!("unknown token `{value}`")),
        });
    }
    if let Some(value) = args.get("location") {
        options.set_location(location(value)?);
    }
    if let Some(id) = args.get("accessControl").and_then(Value::as_u64) {
        options.set_access_control(access_control(id)?);
    }
    if let Some(value) = args.get("synchronizable").and_then(Value::as_bool) {
        options.set_synchronizable(value);
    }
    Ok(options)
}

fn item_search_options(args: &Value) -> R<ItemSearchOptions> {
    let mut options = ItemSearchOptions::new();
    if let Some(ids) = args.get("keychains").and_then(Value::as_array) {
        let values: R<Vec<_>> = ids
            .iter()
            .map(|id| {
                id.as_u64()
                    .ok_or_else(|| "keychains must contain handles".into())
                    .and_then(keychain)
            })
            .collect();
        options.keychains(&values?);
    }
    if args
        .get("ignoreLegacyKeychains")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        options.ignore_legacy_keychains();
    }
    if let Some(value) = args.get("class").and_then(Value::as_str) {
        options.class(match value {
            "genericPassword" => ItemClass::generic_password(),
            "internetPassword" => ItemClass::internet_password(),
            "certificate" => ItemClass::certificate(),
            "key" => ItemClass::key(),
            "identity" => ItemClass::identity(),
            _ => return Err(format!("unknown item class `{value}`")),
        });
    }
    if args.get("caseInsensitive").is_some() {
        options.case_insensitive(optional_bool(args, "caseInsensitive")?);
    }
    if let Some(value) = args.get("keyClass").and_then(Value::as_str) {
        options.key_class(match value {
            "public" => KeyClass::public(),
            "private" => KeyClass::private(),
            "symmetric" => KeyClass::symmetric(),
            _ => return Err(format!("unknown key class `{value}`")),
        });
    }
    if let Some(value) = args.get("loadRefs").and_then(Value::as_bool) {
        options.load_refs(value);
    }
    if let Some(value) = args.get("loadAttributes").and_then(Value::as_bool) {
        options.load_attributes(value);
    }
    if let Some(value) = args.get("loadData").and_then(Value::as_bool) {
        options.load_data(value);
    }
    if let Some(value) = args.get("limit") {
        if value == "all" {
            options.limit(Limit::All);
        } else if let Some(limit) = value.as_i64() {
            options.limit(limit);
        } else {
            return Err("limit must be `all` or an integer".into());
        }
    }
    macro_rules! set_string {
        ($field:literal, $method:ident) => {
            if let Some(value) = args.get($field).and_then(Value::as_str) {
                options.$method(value);
            }
        };
    }
    set_string!("label", label);
    set_string!("service", service);
    set_string!("subject", subject);
    set_string!("account", account);
    set_string!("accessGroup", access_group);
    if args.get("trustedOnly").is_some() {
        options.trusted_only(optional_bool(args, "trustedOnly")?);
    }
    if let Some(value) = args.get("cloudSync") {
        options.cloud_sync(match value.as_str() {
            Some("yes") => CloudSync::MatchSyncYes,
            Some("no") => CloudSync::MatchSyncNo,
            Some("any") => CloudSync::MatchSyncAny,
            _ => return Err("cloudSync must be yes, no, or any".into()),
        });
    }
    macro_rules! set_bytes {
        ($field:literal, $method:ident) => {
            if let Some(value) = args.get($field).and_then(Value::as_str) {
                options.$method(&decode_hex(value)?);
            }
        };
    }
    set_bytes!("publicKeyHash", pub_key_hash);
    set_bytes!("serialNumber", serial_number);
    set_bytes!("applicationLabel", application_label);
    if args
        .get("accessGroupToken")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        options.access_group_token();
    }
    if let Some(value) = args.get("skipAuthenticatedItems").and_then(Value::as_bool) {
        options.skip_authenticated_items(value);
    }
    Ok(options)
}

fn item_class(value: &str) -> R<ItemClass> {
    match value {
        "genericPassword" => Ok(ItemClass::generic_password()),
        "internetPassword" => Ok(ItemClass::internet_password()),
        "certificate" => Ok(ItemClass::certificate()),
        "key" => Ok(ItemClass::key()),
        "identity" => Ok(ItemClass::identity()),
        _ => Err(format!("unknown item class `{value}`")),
    }
}

fn location(value: &Value) -> R<Location> {
    if let Some(name) = value.as_str() {
        return match name {
            "defaultFileKeychain" => Ok(Location::DefaultFileKeychain),
            "dataProtectionKeychain" => Ok(Location::DataProtectionKeychain),
            _ => Err(format!("unknown location `{name}`")),
        };
    }
    if let Some(id) = value.get("fileKeychain").and_then(Value::as_u64) {
        return Ok(Location::FileKeychain(keychain(id)?));
    }
    Err("invalid item location".into())
}

fn add_ref(value: &Value) -> R<AddRef> {
    let id = value
        .get("handle")
        .and_then(Value::as_u64)
        .ok_or("item reference needs a handle")?;
    match value.get("type").and_then(Value::as_str) {
        Some("key") => Ok(AddRef::Key(key(id)?)),
        Some("identity") => Ok(AddRef::Identity(identity(id)?)),
        Some("certificate") => Ok(AddRef::Certificate(certificate(id)?)),
        Some(kind) => Err(format!("unknown item reference type `{kind}`")),
        None => Err("item reference needs a type".into()),
    }
}

fn item_add_options(args: &Value) -> R<ItemAddOptions> {
    let value = arg(args, "value")?;
    let add_value = if let Some(data) = value.get("data").and_then(Value::as_str) {
        ItemAddValue::Data {
            class: item_class(
                value
                    .get("class")
                    .and_then(Value::as_str)
                    .ok_or("data item value needs a class")?,
            )?,
            data: CFData::from_buffer(&decode_hex(data)?),
        }
    } else {
        ItemAddValue::Ref(add_ref(value)?)
    };
    let mut options = ItemAddOptions::new(add_value);
    macro_rules! set_string {
        ($field:literal, $method:ident) => {
            if let Some(value) = args.get($field).and_then(Value::as_str) {
                options.$method(value);
            }
        };
    }
    set_string!("accountName", set_account_name);
    set_string!("accessGroup", set_access_group);
    set_string!("comment", set_comment);
    set_string!("description", set_description);
    set_string!("label", set_label);
    set_string!("service", set_service);
    if let Some(value) = args.get("location") {
        options.set_location(location(value)?);
    }
    Ok(options)
}

fn item_update_options(args: &Value) -> R<ItemUpdateOptions> {
    let mut options = ItemUpdateOptions::new();
    if let Some(value) = args.get("value") {
        if let Some(data) = value.get("data").and_then(Value::as_str) {
            options.set_value(ItemUpdateValue::Data(CFData::from_buffer(&decode_hex(
                data,
            )?)));
        } else {
            options.set_value(ItemUpdateValue::Ref(add_ref(value)?));
        }
    }
    if let Some(value) = args.get("class").and_then(Value::as_str) {
        options.set_class(item_class(value)?);
    }
    macro_rules! set_string {
        ($field:literal, $method:ident) => {
            if let Some(value) = args.get($field).and_then(Value::as_str) {
                options.$method(value);
            }
        };
    }
    set_string!("accountName", set_account_name);
    set_string!("accessGroup", set_access_group);
    set_string!("comment", set_comment);
    set_string!("description", set_description);
    set_string!("label", set_label);
    set_string!("service", set_service);
    if let Some(value) = args.get("location") {
        options.set_location(location(value)?);
    }
    Ok(options)
}

fn authorization_items(
    value: Option<&Value>,
) -> R<Option<security_framework::authorization::AuthorizationItemSetStorage>> {
    let Some(items) = value else {
        return Ok(None);
    };
    if items.is_null() {
        return Ok(None);
    }
    let mut builder = AuthorizationItemSetBuilder::new();
    for item in items
        .as_array()
        .ok_or("authorization items must be an array")?
    {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or("authorization item needs a name")?;
        builder = match item.get("value") {
            None | Some(Value::Null) => builder.add_right(name),
            Some(Value::String(value))
                if item.get("string").and_then(Value::as_bool).unwrap_or(false) =>
            {
                builder.add_string(name, value.as_str())
            }
            Some(Value::String(value)) => builder.add_data(name, decode_hex(value)?),
            _ => return Err("authorization item value must be hex data, a string, or null".into()),
        }
        .map_err(|error| error.to_string())?;
    }
    Ok(Some(builder.build()))
}

fn trust_settings_domain(value: &str) -> R<TrustSettingsDomain> {
    match value {
        "user" => Ok(TrustSettingsDomain::User),
        "admin" => Ok(TrustSettingsDomain::Admin),
        "system" => Ok(TrustSettingsDomain::System),
        _ => Err(format!("unknown trust settings domain `{value}`")),
    }
}

fn property_json(value: PropertyType) -> Value {
    match value {
        PropertyType::String(value) => json!({ "type": "string", "value": value.to_string() }),
        PropertyType::Section(value) => {
            json!({ "type": "section", "value": value.iter().map(|item| json!({ "label": item.label().to_string(), "value": property_json(item.get()) })).collect::<Vec<_>>() })
        }
        _ => json!({ "type": "unknown" }),
    }
}

fn ssl_protocol(value: &str) -> R<SslProtocol> {
    match value {
        "all" => Ok(SslProtocol::ALL),
        "dtls1" => Ok(SslProtocol::DTLS1),
        "ssl2" => Ok(SslProtocol::SSL2),
        "ssl3" => Ok(SslProtocol::SSL3),
        "ssl3Only" => Ok(SslProtocol::SSL3_ONLY),
        "tls1" => Ok(SslProtocol::TLS1),
        "tls11" => Ok(SslProtocol::TLS11),
        "tls12" => Ok(SslProtocol::TLS12),
        "tls13" => Ok(SslProtocol::TLS13),
        "tls1Only" => Ok(SslProtocol::TLS1_ONLY),
        "unknown" => Ok(SslProtocol::UNKNOWN),
        _ => Err(format!("unknown SSL protocol `{value}`")),
    }
}

fn ssl_protocol_name(value: SslProtocol) -> &'static str {
    if value == SslProtocol::ALL {
        "all"
    } else if value == SslProtocol::DTLS1 {
        "dtls1"
    } else if value == SslProtocol::SSL2 {
        "ssl2"
    } else if value == SslProtocol::SSL3 {
        "ssl3"
    } else if value == SslProtocol::SSL3_ONLY {
        "ssl3Only"
    } else if value == SslProtocol::TLS1 {
        "tls1"
    } else if value == SslProtocol::TLS11 {
        "tls11"
    } else if value == SslProtocol::TLS12 {
        "tls12"
    } else if value == SslProtocol::TLS13 {
        "tls13"
    } else if value == SslProtocol::TLS1_ONLY {
        "tls1Only"
    } else {
        "unknown"
    }
}

fn session_state_name(value: SessionState) -> &'static str {
    if value == SessionState::ABORTED {
        "aborted"
    } else if value == SessionState::CLOSED {
        "closed"
    } else if value == SessionState::CONNECTED {
        "connected"
    } else if value == SessionState::HANDSHAKE {
        "handshake"
    } else {
        "idle"
    }
}

fn client_certificate_state_name(value: SslClientCertificateState) -> &'static str {
    if value == SslClientCertificateState::REJECTED {
        "rejected"
    } else if value == SslClientCertificateState::REQUESTED {
        "requested"
    } else if value == SslClientCertificateState::SENT {
        "sent"
    } else {
        "none"
    }
}

fn handshake_value(value: Result<SslStream<TcpStream>, HandshakeError<TcpStream>>) -> Value {
    match value {
        Ok(stream) => {
            json!({ "kind": "stream", "handle": insert(NativeObject::SslStream(stream)) })
        }
        Err(HandshakeError::Failure(error)) => {
            json!({ "kind": "failure", "error": error.to_string() })
        }
        Err(HandshakeError::Interrupted(stream)) => {
            let error = stream.error().to_string();
            let server_auth_completed = stream.server_auth_completed();
            let client_cert_requested = stream.client_cert_requested();
            let would_block = stream.would_block();
            let client_hello_received = stream.client_hello_received();
            json!({
                "kind": "interrupted",
                "error": error,
                "handle": insert(NativeObject::MidHandshakeSslStream(stream)),
                "serverAuthCompleted": server_auth_completed,
                "clientCertRequested": client_cert_requested,
                "wouldBlock": would_block,
                "clientHelloReceived": client_hello_received
            })
        }
    }
}

fn client_handshake_value(
    value: Result<SslStream<TcpStream>, ClientHandshakeError<TcpStream>>,
) -> Value {
    match value {
        Ok(stream) => {
            json!({ "kind": "stream", "handle": insert(NativeObject::SslStream(stream)) })
        }
        Err(ClientHandshakeError::Failure(error)) => {
            json!({ "kind": "failure", "error": error.to_string() })
        }
        Err(ClientHandshakeError::Interrupted(builder)) => {
            let error = builder.error().to_string();
            json!({
                "kind": "interrupted",
                "error": error,
                "handle": insert(NativeObject::MidHandshakeClientBuilder(builder))
            })
        }
    }
}

fn client_builder(config: &Value) -> R<ClientBuilder> {
    let mut builder = ClientBuilder::new();
    if let Some(values) = config.get("anchorCertificates").and_then(Value::as_array) {
        let certs: R<Vec<_>> = values
            .iter()
            .map(|v| {
                v.as_u64()
                    .ok_or("anchor certificates must be handles".into())
                    .and_then(certificate)
            })
            .collect();
        builder.anchor_certificates(&certs?);
    }
    if let Some(value) = config
        .get("trustAnchorCertificatesOnly")
        .and_then(Value::as_bool)
    {
        builder.trust_anchor_certificates_only(value);
    }
    if let Some(value) = config
        .get("dangerAcceptInvalidCerts")
        .and_then(Value::as_bool)
    {
        builder.danger_accept_invalid_certs(value);
    }
    if let Some(value) = config.get("useSni").and_then(Value::as_bool) {
        builder.use_sni(value);
    }
    if let Some(value) = config
        .get("dangerAcceptInvalidHostnames")
        .and_then(Value::as_bool)
    {
        builder.danger_accept_invalid_hostnames(value);
    }
    if let Some(values) = config.get("whitelistCiphers").and_then(Value::as_array) {
        builder.whitelist_ciphers(
            &values
                .iter()
                .map(|v| CipherSuite::from_raw(v.as_u64().unwrap_or(0) as u16))
                .collect::<Vec<_>>(),
        );
    }
    if let Some(values) = config.get("blacklistCiphers").and_then(Value::as_array) {
        builder.blacklist_ciphers(
            &values
                .iter()
                .map(|v| CipherSuite::from_raw(v.as_u64().unwrap_or(0) as u16))
                .collect::<Vec<_>>(),
        );
    }
    if let Some(value) = config.get("identity") {
        let chain: R<Vec<_>> = value
            .get("chain")
            .and_then(Value::as_array)
            .ok_or("identity chain must be an array")?
            .iter()
            .map(|v| {
                v.as_u64()
                    .ok_or("identity chain must contain handles".into())
                    .and_then(certificate)
            })
            .collect();
        builder.identity(
            &identity(
                value
                    .get("handle")
                    .and_then(Value::as_u64)
                    .ok_or("identity needs a handle")?,
            )?,
            &chain?,
        );
    }
    if let Some(value) = config.get("protocolMin").and_then(Value::as_str) {
        builder.protocol_min(ssl_protocol(value)?);
    }
    if let Some(value) = config.get("protocolMax").and_then(Value::as_str) {
        builder.protocol_max(ssl_protocol(value)?);
    }
    if let Some(values) = config.get("alpnProtocols").and_then(Value::as_array) {
        let values: R<Vec<_>> = values
            .iter()
            .map(|v| v.as_str().ok_or("ALPN protocols must be strings".into()))
            .collect();
        builder.alpn_protocols(&values?);
    }
    if let Some(value) = config.get("enableSessionTickets").and_then(Value::as_bool) {
        builder.enable_session_tickets(value);
    }
    Ok(builder)
}

fn server_builder(config: &Value) -> R<ServerBuilder> {
    if let Some(data) = config.get("pkcs12").and_then(Value::as_str) {
        ServerBuilder::from_pkcs12(
            &decode_hex(data)?,
            config
                .get("passphrase")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
        .map_err(|e| e.to_string())
    } else {
        let certs: R<Vec<_>> = config
            .get("certificates")
            .and_then(Value::as_array)
            .ok_or("certificates must be an array")?
            .iter()
            .map(|v| {
                v.as_u64()
                    .ok_or("certificates must contain handles".into())
                    .and_then(certificate)
            })
            .collect();
        Ok(ServerBuilder::new(
            &identity(
                config
                    .get("identity")
                    .and_then(Value::as_u64)
                    .ok_or("identity handle is required")?,
            )?,
            &certs?,
        ))
    }
}

fn cms_chain_mode(value: i64) -> R<CMSCertificateChainMode> {
    match value {
        0 => Ok(CMSCertificateChainMode::kCMSCertificateNone),
        1 => Ok(CMSCertificateChainMode::kCMSCertificateSignerOnly),
        2 => Ok(CMSCertificateChainMode::kCMSCertificateChain),
        3 => Ok(CMSCertificateChainMode::kCMSCertificateChainWithRoot),
        4 => Ok(CMSCertificateChainMode::kCMSCertificateChainWithRootOrFail),
        _ => Err(format!("unknown CMS certificate chain mode `{value}`")),
    }
}

fn cms_signer_status(value: CMSSignerStatus) -> &'static str {
    match value {
        CMSSignerStatus::kCMSSignerUnsigned => "unsigned",
        CMSSignerStatus::kCMSSignerValid => "valid",
        CMSSignerStatus::kCMSSignerNeedsDetachedContent => "needsDetachedContent",
        CMSSignerStatus::kCMSSignerInvalidSignature => "invalidSignature",
        CMSSignerStatus::kCMSSignerInvalidCert => "invalidCert",
        CMSSignerStatus::kCMSSignerInvalidIndex => "invalidIndex",
    }
}

fn search_result(value: SearchResult) -> Value {
    match value {
        SearchResult::Data(data) => json!({ "kind": "data", "data": hex(data) }),
        SearchResult::Dict(dict) => {
            let simplified = SearchResult::Dict(dict).simplify_dict().unwrap_or_default();
            json!({ "kind": "attributes", "attributes": simplified })
        }
        SearchResult::Ref(reference) => match reference {
            Reference::Certificate(value) => {
                json!({ "kind": "reference", "type": "certificate", "handle": insert(NativeObject::Certificate(value)) })
            }
            Reference::Identity(value) => {
                json!({ "kind": "reference", "type": "identity", "handle": insert(NativeObject::Identity(value)) })
            }
            Reference::Key(value) => {
                json!({ "kind": "reference", "type": "key", "handle": insert(NativeObject::Key(value)) })
            }
            Reference::KeychainItem(value) => {
                json!({ "kind": "reference", "type": "keychainItem", "handle": insert(NativeObject::KeychainItem(value)) })
            }
            _ => json!({ "kind": "other" }),
        },
        SearchResult::Other => json!({ "kind": "other" }),
    }
}

fn dispatch(operation: &str, args: &Value) -> R<Value> {
    match operation {
        "release" => {
            let id = handle(args, "handle")?;
            REGISTRY.with(|registry| registry.borrow_mut().objects.remove(&id));
            Ok(Value::Null)
        }
        "error.message" => {
            let code = arg(args, "code")?
                .as_i64()
                .ok_or("`code` must be an integer")? as i32;
            Ok(security_framework::base::Error::from_code(code)
                .message()
                .map(Value::String)
                .unwrap_or(Value::Null))
        }

        "accessControl.create" => Ok(insert(NativeObject::AccessControl(
            SecAccessControl::create_with_protection(
                protection(optional_string(args, "protection")?)?,
                number(args, "flags")? as usize,
            )
            .map_err(|e| e.to_string())?,
        ))),

        "certificate.fromDer" => Ok(insert(NativeObject::Certificate(
            SecCertificate::from_der(&bytes(args, "data")?).map_err(|e| e.to_string())?,
        ))),
        "certificate.toDer" => Ok(hex(certificate(handle(args, "handle")?)?.to_der())),
        "certificate.addToKeychain" => {
            let chain = args
                .get("keychain")
                .and_then(Value::as_u64)
                .map(keychain)
                .transpose()?;
            certificate(handle(args, "handle")?)?
                .add_to_keychain(chain)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "certificate.subjectSummary" => Ok(json!(
            certificate(handle(args, "handle")?)?.subject_summary()
        )),
        "certificate.emailAddresses" => Ok(json!(
            certificate(handle(args, "handle")?)?
                .email_addresses()
                .map_err(|e| e.to_string())?
        )),
        "certificate.issuer" => Ok(hex(certificate(handle(args, "handle")?)?.issuer())),
        "certificate.subject" => Ok(hex(certificate(handle(args, "handle")?)?.subject())),
        "certificate.serialNumberBytes" => Ok(hex(certificate(handle(args, "handle")?)?
            .serial_number_bytes()
            .map_err(|e| e.to_string())?)),
        "certificate.publicKeyInfoDer" => Ok(certificate(handle(args, "handle")?)?
            .public_key_info_der()
            .map_err(|e| e.to_string())?
            .map(hex)
            .unwrap_or(Value::Null)),
        "certificate.publicKey" | "certificate.publicKeyMacos" => Ok(insert(NativeObject::Key(
            certificate(handle(args, "handle")?)?
                .public_key()
                .map_err(|e| e.to_string())?,
        ))),
        "certificate.commonName" => Ok(json!(
            certificate(handle(args, "handle")?)?
                .common_name()
                .map_err(|e| e.to_string())?
        )),
        "certificate.fingerprint" => Ok(hex(certificate(handle(args, "handle")?)?
            .fingerprint()
            .map_err(|e| e.to_string())?)),
        "certificate.signatureAlgorithmProperty" => {
            let oid = CertificateOid::x509_v1_signature_algorithm();
            let properties = certificate(handle(args, "handle")?)?
                .properties(Some(&[oid]))
                .map_err(|e| e.to_string())?;
            Ok(properties.get(oid).map(|item| json!({ "label": item.label().to_string(), "value": property_json(item.get()) })).unwrap_or(Value::Null))
        }
        "certificate.delete" => {
            certificate(handle(args, "handle")?)?
                .delete()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }

        "identity.certificate" => Ok(insert(NativeObject::Certificate(
            identity(handle(args, "handle")?)?
                .certificate()
                .map_err(|e| e.to_string())?,
        ))),
        "identity.privateKey" => Ok(insert(NativeObject::Key(
            identity(handle(args, "handle")?)?
                .private_key()
                .map_err(|e| e.to_string())?,
        ))),
        "identity.withCertificate" => {
            let chains: R<Vec<_>> = handles(args, "keychains")?
                .into_iter()
                .map(keychain)
                .collect();
            Ok(insert(NativeObject::Identity(
                SecIdentity::with_certificate(
                    &chains?,
                    &certificate(handle(args, "certificate")?)?,
                )
                .map_err(|e| e.to_string())?,
            )))
        }
        "identity.delete" => {
            identity(handle(args, "handle")?)?
                .delete()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }

        "key.generate" => Ok(insert(NativeObject::Key(
            SecKey::new(&generate_key_options(arg(args, "options")?)?)
                .map_err(|e| e.to_string())?,
        ))),
        "key.fromData" => Ok(insert(NativeObject::Key(
            SecKey::from_data(
                key_type(string(args, "keyType")?)?,
                &CFData::from_buffer(&bytes(args, "data")?),
            )
            .map_err(|e| e.to_string())?,
        ))),
        "key.applicationLabel" => Ok(key(handle(args, "handle")?)?
            .application_label()
            .map(hex)
            .unwrap_or(Value::Null)),
        "key.attributes" => Ok(json!(
            SearchResult::Dict(key(handle(args, "handle")?)?.attributes())
                .simplify_dict()
                .unwrap_or_default()
        )),
        "key.externalRepresentation" => Ok(key(handle(args, "handle")?)?
            .external_representation()
            .map(|data| hex(data.bytes()))
            .unwrap_or(Value::Null)),
        "key.publicKey" => Ok(key(handle(args, "handle")?)?
            .public_key()
            .map(|key| insert(NativeObject::Key(key)))
            .unwrap_or(Value::Null)),
        "key.encrypt" => Ok(hex(key(handle(args, "handle")?)?
            .encrypt_data(
                algorithm(string(args, "algorithm")?)?,
                &bytes(args, "data")?,
            )
            .map_err(|e| e.to_string())?)),
        "key.decrypt" => Ok(hex(key(handle(args, "handle")?)?
            .decrypt_data(
                algorithm(string(args, "algorithm")?)?,
                &bytes(args, "data")?,
            )
            .map_err(|e| e.to_string())?)),
        "key.sign" => Ok(hex(key(handle(args, "handle")?)?
            .create_signature(
                algorithm(string(args, "algorithm")?)?,
                &bytes(args, "data")?,
            )
            .map_err(|e| e.to_string())?)),
        "key.verify" => Ok(json!(
            key(handle(args, "handle")?)?
                .verify_signature(
                    algorithm(string(args, "algorithm")?)?,
                    &bytes(args, "data")?,
                    &bytes(args, "signature")?
                )
                .map_err(|e| e.to_string())?
        )),
        "key.exchange" => Ok(hex(key(handle(args, "handle")?)?
            .key_exchange(
                algorithm(string(args, "algorithm")?)?,
                &key(handle(args, "publicKey")?)?,
                number(args, "requestedSize")? as usize,
                optional_bytes(args, "sharedInfo")?.as_deref(),
            )
            .map_err(|e| e.to_string())?)),
        "key.delete" => {
            key(handle(args, "handle")?)?
                .delete()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }

        "policy.ssl" => Ok(insert(NativeObject::Policy(SecPolicy::create_ssl(
            if string(args, "side")? == "server" {
                SslProtocolSide::SERVER
            } else {
                SslProtocolSide::CLIENT
            },
            optional_string(args, "hostname")?,
        )))),
        "policy.revocation" => Ok(insert(NativeObject::Policy(
            SecPolicy::create_revocation(RevocationPolicy::from_bits_retain(
                number(args, "flags")? as usize,
            ))
            .map_err(|e| e.to_string())?,
        ))),
        "policy.x509" => Ok(insert(NativeObject::Policy(SecPolicy::create_x509()))),

        "trust.create" => {
            let certs: R<Vec<_>> = handles(args, "certificates")?
                .into_iter()
                .map(certificate)
                .collect();
            let policies: R<Vec<_>> = handles(args, "policies")?.into_iter().map(policy).collect();
            Ok(insert(NativeObject::Trust(
                SecTrust::create_with_certificates(&certs?, &policies?)
                    .map_err(|e| e.to_string())?,
            )))
        }
        "trust.copyAnchors" => Ok(Value::Array(
            SecTrust::copy_anchor_certificates()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|value| insert(NativeObject::Certificate(value)))
                .collect(),
        )),
        "trust.setVerifyDate" => {
            let mut value = trust(handle(args, "handle")?)?;
            value
                .set_trust_verify_date(&CFDate::new(
                    number(args, "timestamp")? as f64 - 978_307_200.0,
                ))
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.setAnchors" => {
            let mut value = trust(handle(args, "handle")?)?;
            let certs: R<Vec<_>> = handles(args, "certificates")?
                .into_iter()
                .map(certificate)
                .collect();
            value
                .set_anchor_certificates(&certs?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.setAnchorsOnly" => {
            let mut value = trust(handle(args, "handle")?)?;
            value
                .set_trust_anchor_certificates_only(boolean(args, "only")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.setPolicy" => {
            let mut value = trust(handle(args, "handle")?)?;
            value
                .set_policy(&policy(handle(args, "policy")?)?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.setOptions" => {
            let mut value = trust(handle(args, "handle")?)?;
            value
                .set_options(TrustOptions::from_bits_retain(number(args, "flags")? as u32))
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.getNetworkFetchAllowed" => {
            let mut value = trust(handle(args, "handle")?)?;
            Ok(json!(
                value
                    .get_network_fetch_allowed()
                    .map_err(|e| e.to_string())?
            ))
        }
        "trust.setNetworkFetchAllowed" => {
            let mut value = trust(handle(args, "handle")?)?;
            value
                .set_network_fetch_allowed(boolean(args, "allowed")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.setOcspResponse" => {
            let mut value = trust(handle(args, "handle")?)?;
            let values: R<Vec<_>> = arg(args, "responses")?
                .as_array()
                .ok_or("responses must be an array")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or("responses must contain hex strings".into())
                        .and_then(decode_hex)
                })
                .collect();
            value
                .set_trust_ocsp_response(values?.into_iter())
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.setSignedCertificateTimestamps" => {
            let mut value = trust(handle(args, "handle")?)?;
            let values: R<Vec<_>> = arg(args, "timestamps")?
                .as_array()
                .ok_or("timestamps must be an array")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or("timestamps must contain hex strings".into())
                        .and_then(decode_hex)
                })
                .collect();
            value
                .set_signed_certificate_timestamps(values?.into_iter())
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.copyPublicKey" => {
            let mut value = trust(handle(args, "handle")?)?;
            Ok(insert(NativeObject::Key(
                value.copy_public_key().map_err(|e| e.to_string())?,
            )))
        }
        "trust.evaluate" => {
            #[allow(deprecated)]
            let value = trust(handle(args, "handle")?)?
                .evaluate()
                .map_err(|e| e.to_string())?;
            Ok(json!({ "success": value.success(), "debug": format!("{value:?}") }))
        }
        "trust.evaluateWithError" => {
            trust(handle(args, "handle")?)?
                .evaluate_with_error()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trust.chain" => Ok(Value::Array(
            trust(handle(args, "handle")?)?
                .chain()
                .into_iter()
                .map(|value| insert(NativeObject::Certificate(value)))
                .collect(),
        )),
        "trust.certificateCount" => Ok(json!(trust(handle(args, "handle")?)?.certificate_count())),
        "trust.certificateAtIndex" => Ok(trust(handle(args, "handle")?)?
            .certificate_at_index(number(args, "index")? as isize)
            .map(|value| insert(NativeObject::Certificate(value)))
            .unwrap_or(Value::Null)),

        "random.copyBytes" => {
            let mut data = vec![0; number(args, "length")? as usize];
            SecRandom::default()
                .copy_bytes(&mut data)
                .map_err(|e| e.to_string())?;
            Ok(hex(data))
        }

        "password.setGeneric" => {
            set_generic_password(
                string(args, "service")?,
                string(args, "account")?,
                &bytes(args, "password")?,
            )
            .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "password.getGeneric" => Ok(hex(get_generic_password(
            string(args, "service")?,
            string(args, "account")?,
        )
        .map_err(|e| e.to_string())?)),
        "password.deleteGeneric" => {
            delete_generic_password(string(args, "service")?, string(args, "account")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "password.setGenericOptions" => {
            set_generic_password_options(
                &bytes(args, "password")?,
                build_password_options(arg(args, "options")?)?,
            )
            .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "password.getOptions" => Ok(hex(generic_password(build_password_options(arg(
            args, "options",
        )?)?)
        .map_err(|e| e.to_string())?)),
        "password.deleteOptions" => {
            delete_generic_password_options(build_password_options(arg(args, "options")?)?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "password.setInternet" => {
            set_internet_password(
                string(args, "server")?,
                optional_string(args, "securityDomain")?,
                string(args, "account")?,
                string(args, "path")?,
                args.get("port")
                    .and_then(Value::as_u64)
                    .map(|value| value as u16),
                protocol(number(args, "protocol")?)?,
                authentication(number(args, "authenticationType")?)?,
                &bytes(args, "password")?,
            )
            .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "password.getInternet" => Ok(hex(get_internet_password(
            string(args, "server")?,
            optional_string(args, "securityDomain")?,
            string(args, "account")?,
            string(args, "path")?,
            args.get("port")
                .and_then(Value::as_u64)
                .map(|value| value as u16),
            protocol(number(args, "protocol")?)?,
            authentication(number(args, "authenticationType")?)?,
        )
        .map_err(|e| e.to_string())?)),
        "password.deleteInternet" => {
            delete_internet_password(
                string(args, "server")?,
                optional_string(args, "securityDomain")?,
                string(args, "account")?,
                string(args, "path")?,
                args.get("port")
                    .and_then(Value::as_u64)
                    .map(|value| value as u16),
                protocol(number(args, "protocol")?)?,
                authentication(number(args, "authenticationType")?)?,
            )
            .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }

        "pkcs12.import" => {
            let options_value = arg(args, "options")?;
            let mut options = Pkcs12ImportOptions::new();
            if let Some(value) = options_value.get("passphrase").and_then(Value::as_str) {
                options.passphrase(value);
            }
            if let Some(id) = options_value.get("keychain").and_then(Value::as_u64) {
                options.keychain(keychain(id)?);
            }
            Ok(Value::Array(options.import(&bytes(args, "data")?).map_err(|e| e.to_string())?.into_iter().map(|value| json!({
                "label": value.label, "keyId": value.key_id.map(hex),
                "trust": value.trust.map(|v| insert(NativeObject::Trust(v))),
                "certificateChain": value.cert_chain.map(|v| v.into_iter().map(|c| insert(NativeObject::Certificate(c))).collect::<Vec<_>>()),
                "identity": value.identity.map(|v| insert(NativeObject::Identity(v)))
            })).collect()))
        }

        "item.search" => Ok(Value::Array(
            item_search_options(arg(args, "options")?)?
                .search()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(search_result)
                .collect(),
        )),
        "item.delete" => {
            item_search_options(arg(args, "options")?)?
                .delete()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "item.add" => {
            item_add_options(arg(args, "options")?)?
                .add()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "item.update" => {
            update_item(
                &item_search_options(arg(args, "search")?)?,
                &item_update_options(arg(args, "update")?)?,
            )
            .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }

        "keychain.default" => Ok(insert(NativeObject::Keychain(
            SecKeychain::default().map_err(|e| e.to_string())?,
        ))),
        "keychain.defaultForDomain" => {
            let domain = match string(args, "domain")? {
                "user" => SecPreferencesDomain::User,
                "system" => SecPreferencesDomain::System,
                "common" => SecPreferencesDomain::Common,
                "dynamic" => SecPreferencesDomain::Dynamic,
                value => return Err(format!("unknown preferences domain `{value}`")),
            };
            Ok(insert(NativeObject::Keychain(
                SecKeychain::default_for_domain(domain).map_err(|e| e.to_string())?,
            )))
        }
        "keychain.open" => Ok(insert(NativeObject::Keychain(
            SecKeychain::open(string(args, "path")?).map_err(|e| e.to_string())?,
        ))),
        "keychain.create" => {
            let options_value = arg(args, "options")?;
            let mut options = CreateOptions::new();
            if let Some(v) = options_value.get("password").and_then(Value::as_str) {
                options.password(v);
            }
            if let Some(v) = options_value.get("promptUser").and_then(Value::as_bool) {
                options.prompt_user(v);
            }
            Ok(insert(NativeObject::Keychain(
                options
                    .create(string(args, "path")?)
                    .map_err(|e| e.to_string())?,
            )))
        }
        "keychain.unlock" => {
            let mut value = keychain(handle(args, "handle")?)?;
            value
                .unlock(optional_string(args, "password")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychain.setSettings" => {
            let mut value = keychain(handle(args, "handle")?)?;
            let settings_value = arg(args, "settings")?;
            let mut settings = KeychainSettings::new();
            if let Some(v) = settings_value.get("lockOnSleep").and_then(Value::as_bool) {
                settings.set_lock_on_sleep(v);
            }
            if settings_value.get("lockInterval").is_some() {
                settings.set_lock_interval(
                    settings_value
                        .get("lockInterval")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                );
            }
            value.set_settings(&settings).map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychain.userInteractionAllowed" => Ok(json!(
            SecKeychain::user_interaction_allowed().map_err(|e| e.to_string())?
        )),
        "keychain.disableUserInteraction" => Ok(insert(NativeObject::KeychainUserInteractionLock(
            SecKeychain::disable_user_interaction().map_err(|e| e.to_string())?,
        ))),
        "keychain.findGenericPassword" => {
            let chains: R<Vec<_>> = handles(args, "keychains")?
                .into_iter()
                .map(keychain)
                .collect();
            let (password, item) = find_generic_password(
                if chains.as_ref()?.is_empty() {
                    None
                } else {
                    Some(chains.as_ref()?)
                },
                string(args, "service")?,
                string(args, "account")?,
            )
            .map_err(|e| e.to_string())?;
            Ok(
                json!({ "password": hex(password.as_ref()), "item": insert(NativeObject::KeychainItem(item)) }),
            )
        }
        "keychain.findInternetPassword" => {
            let chains: R<Vec<_>> = handles(args, "keychains")?
                .into_iter()
                .map(keychain)
                .collect();
            let (password, item) = find_internet_password(
                if chains.as_ref()?.is_empty() {
                    None
                } else {
                    Some(chains.as_ref()?)
                },
                string(args, "server")?,
                optional_string(args, "securityDomain")?,
                string(args, "account")?,
                string(args, "path")?,
                args.get("port").and_then(Value::as_u64).map(|v| v as u16),
                protocol(number(args, "protocol")?)?,
                authentication(number(args, "authenticationType")?)?,
            )
            .map_err(|e| e.to_string())?;
            Ok(
                json!({ "password": hex(password.as_ref()), "item": insert(NativeObject::KeychainItem(item)) }),
            )
        }
        "keychain.setGenericPassword" => {
            keychain(handle(args, "handle")?)?
                .set_generic_password(
                    string(args, "service")?,
                    string(args, "account")?,
                    &bytes(args, "password")?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychain.addGenericPassword" => {
            keychain(handle(args, "handle")?)?
                .add_generic_password(
                    string(args, "service")?,
                    string(args, "account")?,
                    &bytes(args, "password")?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychain.setInternetPassword" => {
            keychain(handle(args, "handle")?)?
                .set_internet_password(
                    string(args, "server")?,
                    optional_string(args, "securityDomain")?,
                    string(args, "account")?,
                    string(args, "path")?,
                    args.get("port").and_then(Value::as_u64).map(|v| v as u16),
                    protocol(number(args, "protocol")?)?,
                    authentication(number(args, "authenticationType")?)?,
                    &bytes(args, "password")?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychain.addInternetPassword" => {
            keychain(handle(args, "handle")?)?
                .add_internet_password(
                    string(args, "server")?,
                    optional_string(args, "securityDomain")?,
                    string(args, "account")?,
                    string(args, "path")?,
                    args.get("port").and_then(Value::as_u64).map(|v| v as u16),
                    protocol(number(args, "protocol")?)?,
                    authentication(number(args, "authenticationType")?)?,
                    &bytes(args, "password")?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychainItem.setPassword" => {
            let mut value = keychain_item(handle(args, "handle")?)?;
            value
                .set_password(&bytes(args, "password")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "keychainItem.delete" => {
            keychain_item(handle(args, "handle")?)?.delete();
            Ok(Value::Null)
        }

        "import.import" => {
            let config = arg(args, "options")?;
            let mut items = SecItems::default();
            let mut options = ImportOptions::new();
            if let Some(value) = config.get("filename").and_then(Value::as_str) {
                options.filename(value);
            }
            if config
                .get("pkcs12")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                options.pkcs12();
            }
            if let Some(value) = config.get("passphrase").and_then(Value::as_str) {
                options.passphrase(value);
            }
            if let Some(value) = config.get("passphraseBytes").and_then(Value::as_str) {
                options.passphrase_bytes(&decode_hex(value)?);
            }
            if let Some(value) = config.get("securePassphrase").and_then(Value::as_bool) {
                options.secure_passphrase(value);
            }
            if let Some(value) = config.get("noAccessControl").and_then(Value::as_bool) {
                options.no_access_control(value);
            }
            if let Some(value) = config.get("alertTitle").and_then(Value::as_str) {
                options.alert_title(value);
            }
            if let Some(value) = config.get("alertPrompt").and_then(Value::as_str) {
                options.alert_prompt(value);
            }
            if let Some(id) = config.get("keychain").and_then(Value::as_u64) {
                let chain = keychain(id)?;
                options.keychain(&chain);
            }
            options
                .items(&mut items)
                .import(&bytes(args, "data")?)
                .map_err(|e| e.to_string())?;
            drop(options);
            Ok(json!({
                "certificates": items.certificates.into_iter().map(|v| insert(NativeObject::Certificate(v))).collect::<Vec<_>>(),
                "identities": items.identities.into_iter().map(|v| insert(NativeObject::Identity(v))).collect::<Vec<_>>(),
                "keys": items.keys.into_iter().map(|v| insert(NativeObject::Key(v))).collect::<Vec<_>>()
            }))
        }

        "digest.execute" => {
            let options = arg(args, "options")?;
            let mut builder = DigestBuilder::new();
            if let Some(value) = options.get("type").and_then(Value::as_str) {
                builder.type_(match value {
                    "hmacMd5" => DigestType::hmac_md5(),
                    "hmacSha1" => DigestType::hmac_sha1(),
                    "hmacSha2" => DigestType::hmac_sha2(),
                    "md2" => DigestType::md2(),
                    "md4" => DigestType::md4(),
                    "md5" => DigestType::md5(),
                    "sha1" => DigestType::sha1(),
                    "sha2" => DigestType::sha2(),
                    _ => return Err(format!("unknown digest type `{value}`")),
                });
            }
            if let Some(value) = options.get("length").and_then(Value::as_i64) {
                builder.length(value as isize);
            }
            if let Some(value) = options.get("hmacKey").and_then(Value::as_str) {
                builder.hmac_key(CFData::from_buffer(&decode_hex(value)?));
            }
            Ok(hex(builder
                .execute(&CFData::from_buffer(&bytes(args, "data")?))
                .map_err(|e| e.to_string())?
                .bytes()))
        }
        "encryptTransform.execute" => {
            let options = arg(args, "options")?;
            let mut builder = EncryptBuilder::new();
            if let Some(value) = options.get("padding").and_then(Value::as_str) {
                builder.padding(match value {
                    "none" => Padding::none(),
                    "pkcs1" => Padding::pkcs1(),
                    "pkcs5" => Padding::pkcs5(),
                    "pkcs7" => Padding::pkcs7(),
                    "oaep" => Padding::oaep(),
                    _ => return Err(format!("unknown padding `{value}`")),
                });
            }
            if let Some(value) = options.get("mode").and_then(Value::as_str) {
                builder.mode(match value {
                    "none" => Mode::none(),
                    "ecb" => Mode::ecb(),
                    "cbc" => Mode::cbc(),
                    "cfb" => Mode::cfb(),
                    "ofb" => Mode::ofb(),
                    _ => return Err(format!("unknown mode `{value}`")),
                });
            }
            if let Some(value) = options.get("iv").and_then(Value::as_str) {
                builder.iv(CFData::from_buffer(&decode_hex(value)?));
            }
            let key = key(handle(args, "key")?)?;
            let data = CFData::from_buffer(&bytes(args, "data")?);
            let output = if boolean(args, "encrypt")? {
                builder.encrypt(&key, &data)
            } else {
                builder.decrypt(&key, &data)
            }
            .map_err(|e| e.to_string())?;
            Ok(hex(output.bytes()))
        }

        "ssl.context.create" => Ok(insert(NativeObject::SslContext(
            SslContext::new(
                if string(args, "side")? == "server" {
                    SslProtocolSide::SERVER
                } else {
                    SslProtocolSide::CLIENT
                },
                if string(args, "connectionType")? == "datagram" {
                    SslConnectionType::DATAGRAM
                } else {
                    SslConnectionType::STREAM
                },
            )
            .map_err(|e| e.to_string())?,
        ))),
        "ssl.context.setPeerDomainName" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            value
                .set_peer_domain_name(string(args, "name")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.peerDomainName" => Ok(json!(
            ssl_context(handle(args, "handle")?)?
                .peer_domain_name()
                .map_err(|e| e.to_string())?
        )),
        "ssl.context.setCertificate" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            let certs: R<Vec<_>> = handles(args, "certificates")?
                .into_iter()
                .map(certificate)
                .collect();
            value
                .set_certificate(&identity(handle(args, "identity")?)?, &certs?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.setPeerId" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            value
                .set_peer_id(&bytes(args, "data")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.peerId" => Ok(ssl_context(handle(args, "handle")?)?
            .peer_id()
            .map_err(|e| e.to_string())?
            .map(hex)
            .unwrap_or(Value::Null)),
        "ssl.context.supportedCiphers" => Ok(json!(
            ssl_context(handle(args, "handle")?)?
                .supported_ciphers()
                .map_err(|e| e.to_string())?
                .iter()
                .map(CipherSuite::to_raw)
                .collect::<Vec<_>>()
        )),
        "ssl.context.enabledCiphers" => Ok(json!(
            ssl_context(handle(args, "handle")?)?
                .enabled_ciphers()
                .map_err(|e| e.to_string())?
                .iter()
                .map(CipherSuite::to_raw)
                .collect::<Vec<_>>()
        )),
        "ssl.context.setEnabledCiphers" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            let ciphers = arg(args, "ciphers")?
                .as_array()
                .ok_or("ciphers must be an array")?
                .iter()
                .map(|v| CipherSuite::from_raw(v.as_u64().unwrap_or(0) as u16))
                .collect::<Vec<_>>();
            value
                .set_enabled_ciphers(&ciphers)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.negotiatedCipher" => Ok(json!(
            ssl_context(handle(args, "handle")?)?
                .negotiated_cipher()
                .map_err(|e| e.to_string())?
                .to_raw()
        )),
        "ssl.context.setClientAuthenticate" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            let auth = match string(args, "auth")? {
                "always" => SslAuthenticate::ALWAYS,
                "never" => SslAuthenticate::NEVER,
                "try" => SslAuthenticate::TRY,
                v => return Err(format!("unknown SSL authenticate value `{v}`")),
            };
            value
                .set_client_side_authenticate(auth)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.clientCertificateState" => Ok(json!(client_certificate_state_name(
            ssl_context(handle(args, "handle")?)?
                .client_certificate_state()
                .map_err(|e| e.to_string())?
        ))),
        "ssl.context.peerTrust" => Ok(ssl_context(handle(args, "handle")?)?
            .peer_trust2()
            .map_err(|e| e.to_string())?
            .map(|v| insert(NativeObject::Trust(v)))
            .unwrap_or(Value::Null)),
        "ssl.context.state" => Ok(json!(session_state_name(
            ssl_context(handle(args, "handle")?)?
                .state()
                .map_err(|e| e.to_string())?
        ))),
        "ssl.context.negotiatedProtocol" => Ok(json!(ssl_protocol_name(
            ssl_context(handle(args, "handle")?)?
                .negotiated_protocol_version()
                .map_err(|e| e.to_string())?
        ))),
        "ssl.context.protocolMax" => Ok(json!(ssl_protocol_name(
            ssl_context(handle(args, "handle")?)?
                .protocol_version_max()
                .map_err(|e| e.to_string())?
        ))),
        "ssl.context.setProtocolMax" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            value
                .set_protocol_version_max(ssl_protocol(string(args, "protocol")?)?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.protocolMin" => Ok(json!(ssl_protocol_name(
            ssl_context(handle(args, "handle")?)?
                .protocol_version_min()
                .map_err(|e| e.to_string())?
        ))),
        "ssl.context.setProtocolMin" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            value
                .set_protocol_version_min(ssl_protocol(string(args, "protocol")?)?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.alpnProtocols" => Ok(json!(
            ssl_context(handle(args, "handle")?)?
                .alpn_protocols()
                .map_err(|e| e.to_string())?
        )),
        "ssl.context.setAlpnProtocols" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            let protocols: R<Vec<_>> = arg(args, "protocols")?
                .as_array()
                .ok_or("protocols must be an array")?
                .iter()
                .map(|v| v.as_str().ok_or("protocols must contain strings".into()))
                .collect();
            value
                .set_alpn_protocols(&protocols?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.setSessionTicketsEnabled" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            value
                .set_session_tickets_enabled(boolean(args, "enabled")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.bufferedReadSize" => Ok(json!(
            ssl_context(handle(args, "handle")?)?
                .buffered_read_size()
                .map_err(|e| e.to_string())?
        )),
        "ssl.context.getOption" => {
            let value = ssl_context(handle(args, "handle")?)?;
            let result = match string(args, "option")? {
                "breakOnServerAuth" => value.break_on_server_auth(),
                "breakOnCertRequested" => value.break_on_cert_requested(),
                "breakOnClientAuth" => value.break_on_client_auth(),
                "falseStart" => value.false_start(),
                "sendOneByteRecord" => value.send_one_byte_record(),
                "allowServerIdentityChange" => value.allow_server_identity_change(),
                "fallback" => value.fallback(),
                "breakOnClientHello" => value.break_on_client_hello(),
                v => return Err(format!("unknown SSL option `{v}`")),
            };
            Ok(json!(result.map_err(|e| e.to_string())?))
        }
        "ssl.context.setOption" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            let enabled = boolean(args, "enabled")?;
            #[allow(deprecated)]
            let result = match string(args, "option")? {
                "breakOnServerAuth" => value.set_break_on_server_auth(enabled),
                "breakOnCertRequested" => value.set_break_on_cert_requested(enabled),
                "breakOnClientAuth" => value.set_break_on_client_auth(enabled),
                "falseStart" => value.set_false_start(enabled),
                "sendOneByteRecord" => value.set_send_one_byte_record(enabled),
                "allowServerIdentityChange" => value.set_allow_server_identity_change(enabled),
                "fallback" => value.set_fallback(enabled),
                "breakOnClientHello" => value.set_break_on_client_hello(enabled),
                v => return Err(format!("unknown SSL option `{v}`")),
            };
            result.map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.diffieHellmanParams" => Ok(ssl_context(handle(args, "handle")?)?
            .diffie_hellman_params()
            .map_err(|e| e.to_string())?
            .map(hex)
            .unwrap_or(Value::Null)),
        "ssl.context.setDiffieHellmanParams" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            value
                .set_diffie_hellman_params(&bytes(args, "data")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.certificateAuthorities" => Ok(
            match ssl_context(handle(args, "handle")?)?
                .certificate_authorities()
                .map_err(|e| e.to_string())?
            {
                None => Value::Null,
                Some(values) => Value::Array(
                    values
                        .into_iter()
                        .map(|v| insert(NativeObject::Certificate(v)))
                        .collect(),
                ),
            },
        ),
        "ssl.context.setCertificateAuthorities" => {
            let mut value = ssl_context(handle(args, "handle")?)?;
            let certs: R<Vec<_>> = handles(args, "certificates")?
                .into_iter()
                .map(certificate)
                .collect();
            if boolean(args, "add")? {
                value.add_certificate_authorities(&certs?)
            } else {
                value.set_certificate_authorities(&certs?)
            }
            .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "ssl.context.connect" => {
            let id = handle(args, "handle")?;
            let context = match take_object(id)? {
                NativeObject::SslContext(value) => value,
                _ => return Err(format!("handle {id} has the wrong native type")),
            };
            let stream = TcpStream::connect((string(args, "host")?, number(args, "port")? as u16))
                .map_err(|e| e.to_string())?;
            Ok(handshake_value(context.handshake(stream)))
        }
        "ssl.client.connect" => {
            let stream = TcpStream::connect((string(args, "host")?, number(args, "port")? as u16))
                .map_err(|e| e.to_string())?;
            let builder = client_builder(arg(args, "options")?)?;
            Ok(client_handshake_value(
                builder.handshake(string(args, "domain")?, stream),
            ))
        }
        "ssl.server.context" => {
            let config = arg(args, "options")?;
            Ok(insert(NativeObject::SslContext(
                server_builder(config)?
                    .new_ssl_context()
                    .map_err(|e| e.to_string())?,
            )))
        }
        "ssl.server.accept" => {
            let listener = TcpListener::bind((string(args, "host")?, number(args, "port")? as u16))
                .map_err(|e| e.to_string())?;
            let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
            Ok(insert(NativeObject::SslStream(
                server_builder(arg(args, "options")?)?
                    .handshake(stream)
                    .map_err(|e| e.to_string())?,
            )))
        }
        "ssl.stream.read" => with_ssl_stream(handle(args, "handle")?, |stream| {
            let mut data = vec![0; number(args, "length")? as usize];
            let count = stream.read(&mut data).map_err(|e| e.to_string())?;
            data.truncate(count);
            Ok(hex(data))
        }),
        "ssl.stream.write" => with_ssl_stream(handle(args, "handle")?, |stream| {
            Ok(json!(
                stream
                    .write(&bytes(args, "data")?)
                    .map_err(|e| e.to_string())?
            ))
        }),
        "ssl.stream.flush" => with_ssl_stream(handle(args, "handle")?, |stream| {
            stream.flush().map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }),
        "ssl.stream.close" => with_ssl_stream(handle(args, "handle")?, |stream| {
            stream.close().map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }),
        "ssl.stream.context" => with_ssl_stream(handle(args, "handle")?, |stream| {
            Ok(insert(NativeObject::SslContext(stream.context().clone())))
        }),
        "ssl.stream.info" => with_ssl_stream(handle(args, "handle")?, |stream| {
            Ok(json!({
                "localAddress": stream.get_ref().local_addr().map_err(|e| e.to_string())?.to_string(),
                "peerAddress": stream.get_ref().peer_addr().map_err(|e| e.to_string())?.to_string()
            }))
        }),
        "ssl.midStream.info" => with_mid_handshake_stream(handle(args, "handle")?, |stream| {
            Ok(json!({
                "localAddress": stream.get_ref().local_addr().map_err(|e| e.to_string())?.to_string(),
                "peerAddress": stream.get_ref().peer_addr().map_err(|e| e.to_string())?.to_string()
            }))
        }),
        "ssl.midStream.context" => with_mid_handshake_stream(handle(args, "handle")?, |stream| {
            Ok(insert(NativeObject::SslContext(stream.context().clone())))
        }),
        "ssl.midStream.state" => with_mid_handshake_stream(handle(args, "handle")?, |stream| {
            Ok(json!({
                "error": stream.error().to_string(),
                "serverAuthCompleted": stream.server_auth_completed(),
                "clientCertRequested": stream.client_cert_requested(),
                "wouldBlock": stream.would_block(),
                "clientHelloReceived": stream.client_hello_received()
            }))
        }),
        "ssl.midStream.handshake" => {
            let id = handle(args, "handle")?;
            match take_object(id)? {
                NativeObject::MidHandshakeSslStream(stream) => {
                    Ok(handshake_value(stream.handshake()))
                }
                _ => Err(format!("handle {id} has the wrong native type")),
            }
        }
        "ssl.midClient.info" => with_mid_handshake_client(handle(args, "handle")?, |builder| {
            Ok(json!({
                "localAddress": builder.get_ref().local_addr().map_err(|e| e.to_string())?.to_string(),
                "peerAddress": builder.get_ref().peer_addr().map_err(|e| e.to_string())?.to_string()
            }))
        }),
        "ssl.midClient.error" => with_mid_handshake_client(handle(args, "handle")?, |builder| {
            Ok(json!(builder.error().to_string()))
        }),
        "ssl.midClient.handshake" => {
            let id = handle(args, "handle")?;
            match take_object(id)? {
                NativeObject::MidHandshakeClientBuilder(builder) => {
                    Ok(client_handshake_value(builder.handshake()))
                }
                _ => Err(format!("handle {id} has the wrong native type")),
            }
        }

        "cms.encoder.create" => Ok(insert(NativeObject::CmsEncoder(
            CMSEncoder::create().map_err(|e| e.to_string())?,
        ))),
        "cms.encoder.setSignerAlgorithm" => {
            cms_encoder(handle(args, "handle")?)?
                .set_signer_algorithm(string(args, "algorithm")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.addSigners" => {
            let values: R<Vec<_>> = handles(args, "signers")?
                .into_iter()
                .map(identity)
                .collect();
            cms_encoder(handle(args, "handle")?)?
                .add_signers(&values?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.getSigners" => Ok(Value::Array(
            cms_encoder(handle(args, "handle")?)?
                .get_signers()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|v| insert(NativeObject::Identity(v)))
                .collect(),
        )),
        "cms.encoder.addRecipients" => {
            let values: R<Vec<_>> = handles(args, "recipients")?
                .into_iter()
                .map(certificate)
                .collect();
            cms_encoder(handle(args, "handle")?)?
                .add_recipients(&values?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.getRecipients" => Ok(Value::Array(
            cms_encoder(handle(args, "handle")?)?
                .get_recipients()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|v| insert(NativeObject::Certificate(v)))
                .collect(),
        )),
        "cms.encoder.setDetached" => {
            cms_encoder(handle(args, "handle")?)?
                .set_has_detached_content(boolean(args, "detached")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.getDetached" => Ok(json!(
            cms_encoder(handle(args, "handle")?)?
                .get_has_detached_content()
                .map_err(|e| e.to_string())?
        )),
        "cms.encoder.setContentTypeOid" => {
            cms_encoder(handle(args, "handle")?)?
                .set_encapsulated_content_type_oid(string(args, "oid")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.getContentType" => Ok(hex(cms_encoder(handle(args, "handle")?)?
            .get_encapsulated_content_type()
            .map_err(|e| e.to_string())?)),
        "cms.encoder.addSupportingCerts" => {
            let values: R<Vec<_>> = handles(args, "certificates")?
                .into_iter()
                .map(certificate)
                .collect();
            cms_encoder(handle(args, "handle")?)?
                .add_supporting_certs(&values?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.getSupportingCerts" => Ok(Value::Array(
            cms_encoder(handle(args, "handle")?)?
                .get_supporting_certs()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|v| insert(NativeObject::Certificate(v)))
                .collect(),
        )),
        "cms.encoder.addSignedAttributes" => {
            cms_encoder(handle(args, "handle")?)?
                .add_signed_attributes(SignedAttributes::from_bits_retain(
                    number(args, "flags")? as u32
                ))
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.setChainMode" => {
            cms_encoder(handle(args, "handle")?)?
                .set_certificate_chain_mode(cms_chain_mode(
                    arg(args, "mode")?
                        .as_i64()
                        .ok_or("mode must be an integer")?,
                )?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.getChainMode" => Ok(json!(
            cms_encoder(handle(args, "handle")?)?
                .get_certificate_chain_mode()
                .map_err(|e| e.to_string())? as i32
        )),
        "cms.encoder.update" => {
            cms_encoder(handle(args, "handle")?)?
                .update_content(&bytes(args, "data")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.encoder.encoded" => Ok(hex(cms_encoder(handle(args, "handle")?)?
            .get_encoded_content()
            .map_err(|e| e.to_string())?)),
        "cms.encoder.signerTimestamp" => Ok(json!(
            cms_encoder(handle(args, "handle")?)?
                .get_signer_timestamp(number(args, "index")? as usize)
                .map_err(|e| e.to_string())?
        )),
        "cms.encoder.signerTimestampWithPolicy" => {
            let policy = optional_string(args, "policy")?.map(CFString::new);
            Ok(json!(
                cms_encoder(handle(args, "handle")?)?
                    .get_signer_timestamp_with_policy(
                        policy.as_ref().map(TCFType::as_concrete_TypeRef),
                        number(args, "index")? as usize
                    )
                    .map_err(|e| e.to_string())?
            ))
        }
        "cms.encode" => {
            let signers: R<Vec<_>> = handles(args, "signers")?
                .into_iter()
                .map(identity)
                .collect();
            let recipients: R<Vec<_>> = handles(args, "recipients")?
                .into_iter()
                .map(certificate)
                .collect();
            Ok(hex(cms_encode_content(
                &signers?,
                &recipients?,
                optional_string(args, "contentTypeOid")?,
                boolean(args, "detached")?,
                SignedAttributes::from_bits_retain(number(args, "signedAttributes")? as u32),
                &bytes(args, "content")?,
            )
            .map_err(|e| e.to_string())?))
        }
        "cms.decoder.create" => Ok(insert(NativeObject::CmsDecoder(
            CMSDecoder::create().map_err(|e| e.to_string())?,
        ))),
        "cms.decoder.update" => {
            cms_decoder(handle(args, "handle")?)?
                .update_message(&bytes(args, "data")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.decoder.finalize" => {
            cms_decoder(handle(args, "handle")?)?
                .finalize_message()
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.decoder.setDetached" => {
            cms_decoder(handle(args, "handle")?)?
                .set_detached_content(&bytes(args, "data")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "cms.decoder.getDetached" => Ok(hex(cms_decoder(handle(args, "handle")?)?
            .get_detached_content()
            .map_err(|e| e.to_string())?)),
        "cms.decoder.numSigners" => Ok(json!(
            cms_decoder(handle(args, "handle")?)?
                .get_num_signers()
                .map_err(|e| e.to_string())?
        )),
        "cms.decoder.signerStatus" => {
            let policies: R<Vec<_>> = handles(args, "policies")?.into_iter().map(policy).collect();
            let status = cms_decoder(handle(args, "handle")?)?
                .get_signer_status(number(args, "index")? as usize, &policies?)
                .map_err(|e| e.to_string())?;
            Ok(
                json!({ "signerStatus": cms_signer_status(status.signer_status), "trust": insert(NativeObject::Trust(status.sec_trust)), "certificateVerificationError": status.cert_verify_result.err().map(|e| e.to_string()) }),
            )
        }
        "cms.decoder.signerEmail" => Ok(json!(
            cms_decoder(handle(args, "handle")?)?
                .get_signer_email_address(number(args, "index")? as usize)
                .map_err(|e| e.to_string())?
        )),
        "cms.decoder.isEncrypted" => Ok(json!(
            cms_decoder(handle(args, "handle")?)?
                .is_content_encrypted()
                .map_err(|e| e.to_string())?
        )),
        "cms.decoder.contentType" => Ok(hex(cms_decoder(handle(args, "handle")?)?
            .get_encapsulated_content_type()
            .map_err(|e| e.to_string())?)),
        "cms.decoder.allCerts" => Ok(Value::Array(
            cms_decoder(handle(args, "handle")?)?
                .get_all_certs()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|v| insert(NativeObject::Certificate(v)))
                .collect(),
        )),
        "cms.decoder.content" => Ok(hex(cms_decoder(handle(args, "handle")?)?
            .get_content()
            .map_err(|e| e.to_string())?)),
        "cms.decoder.signingTime" => Ok(json!(
            cms_decoder(handle(args, "handle")?)?
                .get_signer_signing_time(number(args, "index")? as usize)
                .map_err(|e| e.to_string())?
        )),
        "cms.decoder.signerTimestamp" => Ok(json!(
            cms_decoder(handle(args, "handle")?)?
                .get_signer_timestamp(number(args, "index")? as usize)
                .map_err(|e| e.to_string())?
        )),
        "cms.decoder.signerTimestampWithPolicy" => {
            let policy = optional_string(args, "policy")?.map(CFString::new);
            Ok(json!(
                cms_decoder(handle(args, "handle")?)?
                    .get_signer_timestamp_with_policy(
                        policy.as_ref().map(TCFType::as_concrete_TypeRef),
                        number(args, "index")? as usize
                    )
                    .map_err(|e| e.to_string())?
            ))
        }
        "cms.decoder.timestampCertificates" => Ok(Value::Array(
            cms_decoder(handle(args, "handle")?)?
                .get_signer_timestamp_certificates(number(args, "index")? as usize)
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|v| insert(NativeObject::Certificate(v)))
                .collect(),
        )),

        "trustSettings.iter" => {
            let settings = TrustSettings::new(trust_settings_domain(string(args, "domain")?)?);
            Ok(Value::Array(
                settings
                    .iter()
                    .map_err(|e| e.to_string())?
                    .map(|value| insert(NativeObject::Certificate(value)))
                    .collect(),
            ))
        }
        "trustSettings.setAlways" => {
            TrustSettings::new(trust_settings_domain(string(args, "domain")?)?)
                .set_trust_settings_always(&certificate(handle(args, "certificate")?)?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "trustSettings.forCertificate" => {
            let value = TrustSettings::new(trust_settings_domain(string(args, "domain")?)?)
                .tls_trust_settings_for_certificate(&certificate(handle(args, "certificate")?)?)
                .map_err(|e| e.to_string())?;
            Ok(value
                .map(|value| json!(format!("{value:?}")))
                .unwrap_or(Value::Null))
        }

        "codeSigning.requirement" => Ok(insert(NativeObject::Requirement(
            SecRequirement::from_str(string(args, "requirement")?).map_err(|e| e.to_string())?,
        ))),
        "codeSigning.self" => Ok(insert(NativeObject::Code(
            SecCode::for_self(CodeSigningFlags::from_bits_retain(
                number(args, "flags")? as u32
            ))
            .map_err(|e| e.to_string())?,
        ))),
        "codeSigning.guest" => {
            let config = arg(args, "attributes")?;
            let mut attributes = GuestAttributes::new();
            if let Some(pid) = config.get("pid").and_then(Value::as_i64) {
                attributes.set_pid(pid as libc::pid_t);
            }
            let audit_data = config
                .get("auditToken")
                .and_then(Value::as_str)
                .map(decode_hex)
                .transpose()?
                .map(|v| CFData::from_buffer(&v));
            if let Some(value) = &audit_data {
                attributes.set_audit_token(value.as_concrete_TypeRef());
            }
            if let Some(values) = config.get("other").and_then(Value::as_object) {
                for (key, value) in values {
                    let key = CFString::new(key);
                    let value = CFString::new(
                        value
                            .as_str()
                            .ok_or("guest attribute values must be strings")?,
                    );
                    attributes.set_other(key.as_concrete_TypeRef(), value);
                }
            }
            let host = args
                .get("host")
                .and_then(Value::as_u64)
                .map(code)
                .transpose()?;
            Ok(insert(NativeObject::Code(
                SecCode::copy_guest_with_attribues(
                    host.as_ref(),
                    &attributes,
                    CodeSigningFlags::from_bits_retain(number(args, "flags")? as u32),
                )
                .map_err(|e| e.to_string())?,
            )))
        }
        "codeSigning.codeValidity" => {
            code(handle(args, "handle")?)?
                .check_validity(
                    CodeSigningFlags::from_bits_retain(number(args, "flags")? as u32),
                    &requirement(handle(args, "requirement")?)?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "codeSigning.codePath" => Ok(json!(
            code(handle(args, "handle")?)?
                .path(CodeSigningFlags::from_bits_retain(
                    number(args, "flags")? as u32
                ))
                .map_err(|e| e.to_string())?
                .to_path()
                .ok_or("code URL is not a file path")?
                .to_string_lossy()
        )),
        "codeSigning.staticFromPath" => {
            let url = CFURL::from_path(string(args, "path")?, false).ok_or("invalid file path")?;
            Ok(insert(NativeObject::StaticCode(
                SecStaticCode::from_path(
                    &url,
                    CodeSigningFlags::from_bits_retain(number(args, "flags")? as u32),
                )
                .map_err(|e| e.to_string())?,
            )))
        }
        "codeSigning.staticValidity" => {
            static_code(handle(args, "handle")?)?
                .check_validity(
                    CodeSigningFlags::from_bits_retain(number(args, "flags")? as u32),
                    &requirement(handle(args, "requirement")?)?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "codeSigning.staticPath" => Ok(json!(
            static_code(handle(args, "handle")?)?
                .path(CodeSigningFlags::from_bits_retain(
                    number(args, "flags")? as u32
                ))
                .map_err(|e| e.to_string())?
                .to_path()
                .ok_or("code URL is not a file path")?
                .to_string_lossy()
        )),

        "authorization.create" => {
            let authorization = Authorization::new(
                authorization_items(args.get("rights"))?,
                authorization_items(args.get("environment"))?,
                AuthorizationFlags::from_bits_retain(number(args, "flags")? as u32),
            )
            .map_err(|e| e.to_string())?;
            Ok(insert(NativeObject::Authorization(authorization)))
        }
        "authorization.fromExternalForm" => {
            let data = bytes(args, "data")?;
            if data.len() != 32 {
                return Err("authorization external form must be exactly 32 bytes".into());
            }
            let mut form = AuthorizationExternalForm { bytes: [0; 32] };
            for (output, input) in form.bytes.iter_mut().zip(data) {
                *output = input as c_char;
            }
            Ok(insert(NativeObject::Authorization(
                Authorization::try_from(form).map_err(|e| e.to_string())?,
            )))
        }
        "authorization.destroyRights" => {
            let id = handle(args, "handle")?;
            let value = REGISTRY
                .with(|registry| registry.borrow_mut().objects.remove(&id))
                .ok_or_else(|| format!("unknown native handle {id}"))?;
            match value {
                NativeObject::Authorization(value) => {
                    value.destroy_rights();
                    Ok(Value::Null)
                }
                _ => Err(format!("handle {id} has the wrong native type")),
            }
        }
        "authorization.rightExists" => Ok(json!(
            Authorization::right_exists(string(args, "name")?).map_err(|e| e.to_string())?
        )),
        "authorization.getRight" => Ok(json!(format!(
            "{:?}",
            Authorization::get_right(string(args, "name")?).map_err(|e| e.to_string())?
        ))),
        "authorization.removeRight" => with_authorization(handle(args, "handle")?, |value| {
            value
                .remove_right(string(args, "name")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }),
        "authorization.setRight" => with_authorization(handle(args, "handle")?, |value| {
            value
                .set_right(
                    string(args, "name")?,
                    RightDefinition::FromExistingRight(string(args, "existingRight")?),
                    optional_string(args, "description")?,
                    None,
                    optional_string(args, "locale")?,
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }),
        "authorization.copyInfo" => with_authorization(handle(args, "handle")?, |value| {
            Ok(json!(format!(
                "{:?}",
                value
                    .copy_info(optional_string(args, "tag")?)
                    .map_err(|e| e.to_string())?
            )))
        }),
        "authorization.makeExternalForm" => with_authorization(handle(args, "handle")?, |value| {
            let form = value.make_external_form().map_err(|e| e.to_string())?;
            Ok(hex(form.bytes.map(|byte| byte as u8)))
        }),
        "authorization.execute" => with_authorization(handle(args, "handle")?, |value| {
            let arguments = arg(args, "arguments")?
                .as_array()
                .ok_or("arguments must be an array")?
                .iter()
                .map(|v| v.as_str().ok_or("arguments must contain strings"))
                .collect::<Result<Vec<_>, _>>()?;
            let flags = AuthorizationFlags::from_bits_retain(number(args, "flags")? as u32);
            if boolean(args, "piped")? {
                let mut output = Vec::new();
                value
                    .execute_with_privileges_piped(string(args, "command")?, &arguments, flags)
                    .map_err(|e| e.to_string())?
                    .read_to_end(&mut output)
                    .map_err(|e| e.to_string())?;
                Ok(hex(output))
            } else {
                value
                    .execute_with_privileges(string(args, "command")?, &arguments, flags)
                    .map_err(|e| e.to_string())?;
                Ok(Value::Null)
            }
        }),
        "authorization.jobBless" => with_authorization(handle(args, "handle")?, |value| {
            value
                .job_bless(string(args, "label")?)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }),

        _ => Err(format!("unknown native operation `{operation}`")),
    }
}

fn invoke_json(request: &str) -> String {
    let result = (|| -> R<Value> {
        let request: Value = serde_json::from_str(request)
            .map_err(|error| format!("invalid request JSON: {error}"))?;
        let operation = string(&request, "operation")?;
        let args = request.get("args").unwrap_or(&Value::Null);
        dispatch(operation, args)
    })();
    match result {
        Ok(value) => json!({ "ok": true, "value": value }).to_string(),
        Err(message) => json!({ "ok": false, "error": { "message": message } }).to_string(),
    }
}

#[napi]
pub fn invoke(request: String) -> String {
    invoke_json(&request)
}
