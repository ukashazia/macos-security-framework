use std::collections::HashMap;

use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use napi::bindgen_prelude::{Buffer, ClassInstance, Result};
use napi_derive::napi;
use security_framework::access_control::{
    ProtectionMode as NativeProtectionMode, SecAccessControl as NativeSecAccessControl,
};
use security_framework::certificate::SecCertificate as NativeSecCertificate;
use security_framework::identity::SecIdentity as NativeSecIdentity;
use security_framework::item::{Location, SearchResult};
use security_framework::key::{
    Algorithm, GenerateKeyOptions as NativeGenerateKeyOptions, KeyType as NativeKeyType,
    SecKey as NativeSecKey, Token as NativeToken,
};
use security_framework::os::macos::certificate::{PropertyType, SecCertificateExt};
use security_framework::os::macos::certificate_oids::CertificateOid;
use security_framework::os::macos::identity::SecIdentityExt;
use security_framework::os::macos::key::SecKeyExt;
use security_framework::policy::{RevocationPolicy, SecPolicy as NativeSecPolicy};
use security_framework::secure_transport::SslProtocolSide as NativeSslProtocolSide;
use security_framework::trust::{
    SecTrust as NativeSecTrust, TrustOptions, TrustResult as NativeTrustResult,
};

use super::error::napi_error;
use super::keychain::SecKeychain;

#[napi(string_enum)]
#[allow(clippy::enum_variant_names)]
pub enum ProtectionMode {
    AccessibleWhenPasscodeSetThisDeviceOnly,
    AccessibleWhenUnlockedThisDeviceOnly,
    AccessibleWhenUnlocked,
    AccessibleAfterFirstUnlockThisDeviceOnly,
    AccessibleAfterFirstUnlock,
}

impl From<ProtectionMode> for NativeProtectionMode {
    fn from(value: ProtectionMode) -> Self {
        match value {
            ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly => {
                Self::AccessibleWhenPasscodeSetThisDeviceOnly
            }
            ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly => {
                Self::AccessibleWhenUnlockedThisDeviceOnly
            }
            ProtectionMode::AccessibleWhenUnlocked => Self::AccessibleWhenUnlocked,
            ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly => {
                Self::AccessibleAfterFirstUnlockThisDeviceOnly
            }
            ProtectionMode::AccessibleAfterFirstUnlock => Self::AccessibleAfterFirstUnlock,
        }
    }
}

#[napi]
pub struct SecAccessControl {
    pub(crate) inner: NativeSecAccessControl,
}

#[napi]
impl SecAccessControl {
    #[napi(factory)]
    pub fn create_with_flags(flags: u32) -> Result<Self> {
        NativeSecAccessControl::create_with_flags(flags as usize)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn create_with_protection(protection: Option<ProtectionMode>, flags: u32) -> Result<Self> {
        NativeSecAccessControl::create_with_protection(
            protection.map(NativeProtectionMode::from),
            flags as usize,
        )
        .map(|inner| Self { inner })
        .map_err(napi_error)
    }
}

#[napi(object)]
pub struct CertificateProperty {
    pub label: String,
    pub kind: String,
    pub value: Option<String>,
    pub children: Option<Vec<CertificateProperty>>,
}

fn certificate_property(label: String, value: PropertyType) -> CertificateProperty {
    match value {
        PropertyType::String(value) => CertificateProperty {
            label,
            kind: "string".into(),
            value: Some(value.to_string()),
            children: None,
        },
        PropertyType::Section(value) => CertificateProperty {
            label,
            kind: "section".into(),
            value: None,
            children: Some(
                value
                    .iter()
                    .map(|item| certificate_property(item.label().to_string(), item.get()))
                    .collect(),
            ),
        },
        _ => CertificateProperty {
            label,
            kind: "unknown".into(),
            value: None,
            children: None,
        },
    }
}

#[napi]
pub struct SecCertificate {
    pub(crate) inner: NativeSecCertificate,
}

#[napi]
impl SecCertificate {
    #[napi(factory)]
    pub fn from_der(data: Buffer) -> Result<Self> {
        NativeSecCertificate::from_der(&data)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn to_der(&self) -> Buffer {
        self.inner.to_der().into()
    }

    #[napi]
    pub fn add_to_keychain(&self, keychain: Option<&SecKeychain>) -> Result<()> {
        self.inner
            .add_to_keychain(keychain.map(|value| value.inner.clone()))
            .map_err(napi_error)
    }

    #[napi(getter)]
    pub fn subject_summary(&self) -> String {
        self.inner.subject_summary()
    }

    #[napi]
    pub fn email_addresses(&self) -> Result<Vec<String>> {
        self.inner.email_addresses().map_err(napi_error)
    }

    #[napi(getter)]
    pub fn issuer(&self) -> Buffer {
        self.inner.issuer().into()
    }

    #[napi(getter)]
    pub fn subject(&self) -> Buffer {
        self.inner.subject().into()
    }

    #[napi]
    pub fn serial_number_bytes(&self) -> Result<Buffer> {
        self.inner
            .serial_number_bytes()
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn public_key_info_der(&self) -> Result<Option<Buffer>> {
        self.inner
            .public_key_info_der()
            .map(|value| value.map(Buffer::from))
            .map_err(napi_error)
    }

    #[napi]
    pub fn public_key(&self) -> Result<SecKey> {
        SecCertificateExt::public_key(&self.inner)
            .map(|inner| SecKey { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn common_name(&self) -> Result<String> {
        self.inner.common_name().map_err(napi_error)
    }

    #[napi]
    pub fn fingerprint(&self) -> Result<Buffer> {
        self.inner
            .fingerprint()
            .map(|value| value.to_vec().into())
            .map_err(napi_error)
    }

    #[napi]
    pub fn signature_algorithm_property(&self) -> Result<Option<CertificateProperty>> {
        let oid = CertificateOid::x509_v1_signature_algorithm();
        self.inner
            .properties(Some(&[oid]))
            .map(|properties| {
                properties
                    .get(oid)
                    .map(|item| certificate_property(item.label().to_string(), item.get()))
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&self) -> Result<()> {
        self.inner.delete().map_err(napi_error)
    }
}

#[napi]
pub struct SecIdentity {
    pub(crate) inner: NativeSecIdentity,
}

#[napi]
impl SecIdentity {
    #[napi(factory)]
    pub fn with_certificate(
        keychains: Vec<ClassInstance<'_, SecKeychain>>,
        certificate: &SecCertificate,
    ) -> Result<Self> {
        let keychains = keychains
            .iter()
            .map(|keychain| keychain.inner.clone())
            .collect::<Vec<_>>();
        NativeSecIdentity::with_certificate(&keychains, &certificate.inner)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn certificate(&self) -> Result<SecCertificate> {
        self.inner
            .certificate()
            .map(|inner| SecCertificate { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn private_key(&self) -> Result<SecKey> {
        self.inner
            .private_key()
            .map(|inner| SecKey { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&self) -> Result<()> {
        self.inner.delete().map_err(napi_error)
    }
}

#[napi(string_enum)]
pub enum KeyType {
    Rsa,
    Dsa,
    Aes,
    Des,
    TripleDes,
    Rc4,
    Cast,
    Ec,
    EcSecPrimeRandom,
}

impl From<KeyType> for NativeKeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Rsa => Self::rsa(),
            KeyType::Dsa => Self::dsa(),
            KeyType::Aes => Self::aes(),
            KeyType::Des => Self::des(),
            KeyType::TripleDes => Self::triple_des(),
            KeyType::Rc4 => Self::rc4(),
            KeyType::Cast => Self::cast(),
            KeyType::Ec => Self::ec(),
            KeyType::EcSecPrimeRandom => Self::ec_sec_prime_random(),
        }
    }
}

#[napi(string_enum)]
pub enum KeyToken {
    Software,
    SecureEnclave,
}

impl From<KeyToken> for NativeToken {
    fn from(value: KeyToken) -> Self {
        match value {
            KeyToken::Software => Self::Software,
            KeyToken::SecureEnclave => Self::SecureEnclave,
        }
    }
}

#[derive(Default)]
#[napi]
pub struct GenerateKeyOptions {
    inner: NativeGenerateKeyOptions,
}

#[napi]
impl GenerateKeyOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn set_key_type(&mut self, key_type: KeyType) -> &Self {
        self.inner.set_key_type(key_type.into());
        self
    }

    #[napi]
    pub fn set_size_in_bits(&mut self, size_in_bits: u32) -> &Self {
        self.inner.set_size_in_bits(size_in_bits);
        self
    }

    #[napi]
    pub fn set_label(&mut self, label: String) -> &Self {
        self.inner.set_label(label);
        self
    }

    #[napi]
    pub fn set_token(&mut self, token: KeyToken) -> &Self {
        self.inner.set_token(token.into());
        self
    }

    #[napi]
    pub fn set_data_protection_keychain(&mut self) -> &Self {
        self.inner.set_location(Location::DataProtectionKeychain);
        self
    }

    #[napi]
    pub fn set_default_file_keychain(&mut self) -> &Self {
        self.inner.set_location(Location::DefaultFileKeychain);
        self
    }

    #[napi]
    pub fn set_file_keychain(&mut self, keychain: &SecKeychain) -> &Self {
        self.inner
            .set_location(Location::FileKeychain(keychain.inner.clone()));
        self
    }

    #[napi]
    pub fn set_access_control(&mut self, access_control: &SecAccessControl) -> &Self {
        self.inner.set_access_control(access_control.inner.clone());
        self
    }

    #[napi]
    pub fn set_synchronizable(&mut self, synchronizable: bool) -> &Self {
        self.inner.set_synchronizable(synchronizable);
        self
    }
}

#[napi(string_enum)]
pub enum KeyAlgorithm {
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
    RSASignatureMessagePSSSHA512,
}

impl From<KeyAlgorithm> for Algorithm {
    fn from(value: KeyAlgorithm) -> Self {
        macro_rules! algorithms {
            ($($name:ident),+ $(,)?) => {
                match value {
                    $(KeyAlgorithm::$name => Self::$name,)+
                }
            };
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
            RSASignatureMessagePSSSHA512,
        )
    }
}

#[napi]
pub struct SecKey {
    pub(crate) inner: NativeSecKey,
}

#[napi]
impl SecKey {
    #[napi(factory)]
    pub fn generate(options: &GenerateKeyOptions) -> Result<Self> {
        NativeSecKey::new(&options.inner)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn from_data(key_type: KeyType, data: Buffer) -> Result<Self> {
        NativeSecKey::from_data(key_type.into(), &CFData::from_buffer(&data))
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(getter)]
    pub fn application_label(&self) -> Option<Buffer> {
        self.inner.application_label().map(Buffer::from)
    }

    #[napi(getter)]
    pub fn attributes(&self) -> HashMap<String, String> {
        SearchResult::Dict(self.inner.attributes())
            .simplify_dict()
            .unwrap_or_default()
    }

    #[napi(getter)]
    pub fn external_representation(&self) -> Option<Buffer> {
        self.inner
            .external_representation()
            .map(|data| data.bytes().to_vec().into())
    }

    #[napi(getter)]
    pub fn public_key(&self) -> Option<SecKey> {
        self.inner.public_key().map(|inner| SecKey { inner })
    }

    #[napi]
    pub fn encrypt(&self, algorithm: KeyAlgorithm, data: Buffer) -> Result<Buffer> {
        self.inner
            .encrypt_data(algorithm.into(), &data)
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn decrypt(&self, algorithm: KeyAlgorithm, data: Buffer) -> Result<Buffer> {
        self.inner
            .decrypt_data(algorithm.into(), &data)
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn sign(&self, algorithm: KeyAlgorithm, data: Buffer) -> Result<Buffer> {
        self.inner
            .create_signature(algorithm.into(), &data)
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn verify(&self, algorithm: KeyAlgorithm, data: Buffer, signature: Buffer) -> Result<bool> {
        self.inner
            .verify_signature(algorithm.into(), &data, &signature)
            .map_err(napi_error)
    }

    #[napi]
    pub fn exchange(
        &self,
        algorithm: KeyAlgorithm,
        public_key: &SecKey,
        requested_size: u32,
        shared_info: Option<Buffer>,
    ) -> Result<Buffer> {
        self.inner
            .key_exchange(
                algorithm.into(),
                &public_key.inner,
                requested_size as usize,
                shared_info.as_deref(),
            )
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&self) -> Result<()> {
        self.inner.delete().map_err(napi_error)
    }
}

#[napi(string_enum)]
pub enum SslProtocolSide {
    Client,
    Server,
}

impl From<SslProtocolSide> for NativeSslProtocolSide {
    fn from(value: SslProtocolSide) -> Self {
        match value {
            SslProtocolSide::Client => Self::CLIENT,
            SslProtocolSide::Server => Self::SERVER,
        }
    }
}

#[napi]
pub struct SecPolicy {
    pub(crate) inner: NativeSecPolicy,
}

#[napi]
impl SecPolicy {
    #[napi(factory)]
    pub fn ssl(side: SslProtocolSide, hostname: Option<String>) -> Self {
        Self {
            inner: NativeSecPolicy::create_ssl(side.into(), hostname.as_deref()),
        }
    }

    #[napi(factory)]
    pub fn revocation(flags: u32) -> Result<Self> {
        NativeSecPolicy::create_revocation(RevocationPolicy::from_bits_retain(flags as usize))
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn x509() -> Self {
        Self {
            inner: NativeSecPolicy::create_x509(),
        }
    }
}

#[napi(string_enum)]
pub enum TrustResult {
    Deny,
    FatalTrustFailure,
    Invalid,
    OtherError,
    Proceed,
    RecoverableTrustFailure,
    Unspecified,
}

impl From<NativeTrustResult> for TrustResult {
    fn from(value: NativeTrustResult) -> Self {
        if value == NativeTrustResult::DENY {
            Self::Deny
        } else if value == NativeTrustResult::FATAL_TRUST_FAILURE {
            Self::FatalTrustFailure
        } else if value == NativeTrustResult::OTHER_ERROR {
            Self::OtherError
        } else if value == NativeTrustResult::PROCEED {
            Self::Proceed
        } else if value == NativeTrustResult::RECOVERABLE_TRUST_FAILURE {
            Self::RecoverableTrustFailure
        } else if value == NativeTrustResult::UNSPECIFIED {
            Self::Unspecified
        } else {
            Self::Invalid
        }
    }
}

#[napi(object, object_from_js = false)]
pub struct TrustEvaluation {
    pub success: bool,
    pub result: TrustResult,
}

#[napi]
pub struct SecTrust {
    pub(crate) inner: NativeSecTrust,
}

#[napi]
impl SecTrust {
    #[napi(factory)]
    pub fn create(
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
        policies: Vec<ClassInstance<'_, SecPolicy>>,
    ) -> Result<Self> {
        let certificates = certificates
            .iter()
            .map(|certificate| certificate.inner.clone())
            .collect::<Vec<_>>();
        let policies = policies
            .iter()
            .map(|policy| policy.inner.clone())
            .collect::<Vec<_>>();
        NativeSecTrust::create_with_certificates(&certificates, &policies)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn copy_anchor_certificates() -> Result<Vec<SecCertificate>> {
        NativeSecTrust::copy_anchor_certificates()
            .map(|certificates| {
                certificates
                    .into_iter()
                    .map(|inner| SecCertificate { inner })
                    .collect()
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_verify_date(&mut self, timestamp_ms: f64) -> Result<()> {
        let absolute_time = timestamp_ms / 1_000.0 - 978_307_200.0;
        self.inner
            .set_trust_verify_date(&CFDate::new(absolute_time))
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_anchor_certificates(
        &mut self,
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> Result<()> {
        let certificates = certificates
            .iter()
            .map(|certificate| certificate.inner.clone())
            .collect::<Vec<_>>();
        self.inner
            .set_anchor_certificates(&certificates)
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_anchor_certificates_only(&mut self, only: bool) -> Result<()> {
        self.inner
            .set_trust_anchor_certificates_only(only)
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_policy(&mut self, policy: &SecPolicy) -> Result<()> {
        self.inner.set_policy(&policy.inner).map_err(napi_error)
    }

    #[napi]
    pub fn set_options(&mut self, flags: u32) -> Result<()> {
        self.inner
            .set_options(TrustOptions::from_bits_retain(flags))
            .map_err(napi_error)
    }

    #[napi]
    pub fn network_fetch_allowed(&mut self) -> Result<bool> {
        self.inner.get_network_fetch_allowed().map_err(napi_error)
    }

    #[napi]
    pub fn set_network_fetch_allowed(&mut self, allowed: bool) -> Result<()> {
        self.inner
            .set_network_fetch_allowed(allowed)
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_ocsp_response(&mut self, responses: Vec<Buffer>) -> Result<()> {
        self.inner
            .set_trust_ocsp_response(responses.iter())
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_signed_certificate_timestamps(&mut self, timestamps: Vec<Buffer>) -> Result<()> {
        self.inner
            .set_signed_certificate_timestamps(timestamps.iter())
            .map_err(napi_error)
    }

    #[napi]
    pub fn copy_public_key(&mut self) -> Result<SecKey> {
        self.inner
            .copy_public_key()
            .map(|inner| SecKey { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn evaluate(&self) -> Result<TrustEvaluation> {
        let result = self.inner.evaluate().map_err(napi_error)?;
        Ok(TrustEvaluation {
            success: result.success(),
            result: result.into(),
        })
    }

    #[napi]
    pub fn evaluate_with_error(&self) -> Result<()> {
        self.inner.evaluate_with_error().map_err(napi_error)
    }

    #[napi(getter)]
    pub fn chain(&self) -> Vec<SecCertificate> {
        self.inner
            .chain()
            .into_iter()
            .map(|inner| SecCertificate { inner })
            .collect()
    }

    #[napi(getter)]
    pub fn certificate_count(&self) -> i64 {
        self.inner.certificate_count() as i64
    }

    #[napi]
    pub fn certificate_at_index(&self, index: i64) -> Option<SecCertificate> {
        self.inner
            .certificate_at_index(index as isize)
            .map(|inner| SecCertificate { inner })
    }
}
