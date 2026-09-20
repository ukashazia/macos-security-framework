use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use napi::bindgen_prelude::{Buffer, ClassInstance, Result};
use napi_derive::napi;
use security_framework::cms::{
    CMSDecoder as NativeCmsDecoder, CMSEncoder as NativeCmsEncoder,
    SignedAttributes as NativeSignedAttributes, cms_encode_content as native_cms_encode_content,
};
use security_framework_sys::cms::{CMSCertificateChainMode, CMSSignerStatus};

use super::error::napi_error;
use super::security::{SecCertificate, SecIdentity, SecPolicy, SecTrust};

const CF_ABSOLUTE_TIME_UNIX_EPOCH: f64 = 978_307_200.0;

fn timestamp_ms(absolute_time: f64) -> f64 {
    (absolute_time + CF_ABSOLUTE_TIME_UNIX_EPOCH) * 1_000.0
}

fn certificates(
    values: Vec<ClassInstance<'_, SecCertificate>>,
) -> Vec<security_framework::certificate::SecCertificate> {
    values
        .iter()
        .map(|certificate| certificate.inner.clone())
        .collect()
}

fn identities(
    values: Vec<ClassInstance<'_, SecIdentity>>,
) -> Vec<security_framework::identity::SecIdentity> {
    values
        .iter()
        .map(|identity| identity.inner.clone())
        .collect()
}

#[napi(string_enum)]
pub enum CertificateChainMode {
    None,
    SignerOnly,
    Chain,
    ChainWithRoot,
    ChainWithRootOrFail,
}

impl From<CertificateChainMode> for CMSCertificateChainMode {
    fn from(value: CertificateChainMode) -> Self {
        match value {
            CertificateChainMode::None => Self::kCMSCertificateNone,
            CertificateChainMode::SignerOnly => Self::kCMSCertificateSignerOnly,
            CertificateChainMode::Chain => Self::kCMSCertificateChain,
            CertificateChainMode::ChainWithRoot => Self::kCMSCertificateChainWithRoot,
            CertificateChainMode::ChainWithRootOrFail => Self::kCMSCertificateChainWithRootOrFail,
        }
    }
}

impl From<CMSCertificateChainMode> for CertificateChainMode {
    fn from(value: CMSCertificateChainMode) -> Self {
        match value {
            CMSCertificateChainMode::kCMSCertificateNone => Self::None,
            CMSCertificateChainMode::kCMSCertificateSignerOnly => Self::SignerOnly,
            CMSCertificateChainMode::kCMSCertificateChain => Self::Chain,
            CMSCertificateChainMode::kCMSCertificateChainWithRoot => Self::ChainWithRoot,
            CMSCertificateChainMode::kCMSCertificateChainWithRootOrFail => {
                Self::ChainWithRootOrFail
            }
        }
    }
}

#[napi]
pub struct CmsEncoder {
    inner: NativeCmsEncoder,
}

#[napi]
impl CmsEncoder {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        NativeCmsEncoder::create()
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_signer_algorithm(&self, digest_algorithm: String) -> Result<()> {
        self.inner
            .set_signer_algorithm(&digest_algorithm)
            .map_err(napi_error)
    }

    #[napi]
    pub fn add_signers(&self, signers: Vec<ClassInstance<'_, SecIdentity>>) -> Result<()> {
        self.inner
            .add_signers(&identities(signers))
            .map_err(napi_error)
    }

    #[napi]
    pub fn signers(&self) -> Result<Vec<SecIdentity>> {
        self.inner
            .get_signers()
            .map(|values| {
                values
                    .into_iter()
                    .map(|inner| SecIdentity { inner })
                    .collect()
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn add_recipients(&self, recipients: Vec<ClassInstance<'_, SecCertificate>>) -> Result<()> {
        self.inner
            .add_recipients(&certificates(recipients))
            .map_err(napi_error)
    }

    #[napi]
    pub fn recipients(&self) -> Result<Vec<SecCertificate>> {
        self.inner
            .get_recipients()
            .map(|values| {
                values
                    .into_iter()
                    .map(|inner| SecCertificate { inner })
                    .collect()
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_has_detached_content(&self, detached: bool) -> Result<()> {
        self.inner
            .set_has_detached_content(detached)
            .map_err(napi_error)
    }

    #[napi]
    pub fn has_detached_content(&self) -> Result<bool> {
        self.inner.get_has_detached_content().map_err(napi_error)
    }

    #[napi]
    pub fn set_content_type_oid(&self, oid: String) -> Result<()> {
        self.inner
            .set_encapsulated_content_type_oid(&oid)
            .map_err(napi_error)
    }

    #[napi]
    pub fn content_type(&self) -> Result<Buffer> {
        self.inner
            .get_encapsulated_content_type()
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn add_supporting_certificates(
        &self,
        values: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> Result<()> {
        self.inner
            .add_supporting_certs(&certificates(values))
            .map_err(napi_error)
    }

    #[napi]
    pub fn supporting_certificates(&self) -> Result<Vec<SecCertificate>> {
        self.inner
            .get_supporting_certs()
            .map(|values| {
                values
                    .into_iter()
                    .map(|inner| SecCertificate { inner })
                    .collect()
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn add_signed_attributes(&self, flags: u32) -> Result<()> {
        self.inner
            .add_signed_attributes(NativeSignedAttributes::from_bits_retain(flags))
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_certificate_chain_mode(&self, mode: CertificateChainMode) -> Result<()> {
        self.inner
            .set_certificate_chain_mode(mode.into())
            .map_err(napi_error)
    }

    #[napi]
    pub fn certificate_chain_mode(&self) -> Result<CertificateChainMode> {
        self.inner
            .get_certificate_chain_mode()
            .map(CertificateChainMode::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn update(&self, content: Buffer) -> Result<()> {
        self.inner.update_content(&content).map_err(napi_error)
    }

    #[napi]
    pub fn encoded(&self) -> Result<Buffer> {
        self.inner
            .get_encoded_content()
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn signer_timestamp(&self, signer_index: u32) -> Result<f64> {
        self.inner
            .get_signer_timestamp(signer_index as usize)
            .map(timestamp_ms)
            .map_err(napi_error)
    }

    #[napi]
    pub fn signer_timestamp_with_policy(
        &self,
        policy: Option<String>,
        signer_index: u32,
    ) -> Result<f64> {
        let policy = policy.map(|value| CFString::new(&value));
        self.inner
            .get_signer_timestamp_with_policy(
                policy.as_ref().map(|value| value.as_concrete_TypeRef()),
                signer_index as usize,
            )
            .map(timestamp_ms)
            .map_err(napi_error)
    }
}

#[napi]
pub fn cms_encode_content(
    signers: Vec<ClassInstance<'_, SecIdentity>>,
    recipients: Vec<ClassInstance<'_, SecCertificate>>,
    content_type_oid: Option<String>,
    detached_content: bool,
    signed_attributes: u32,
    content: Buffer,
) -> Result<Buffer> {
    native_cms_encode_content(
        &identities(signers),
        &certificates(recipients),
        content_type_oid.as_deref(),
        detached_content,
        NativeSignedAttributes::from_bits_retain(signed_attributes),
        &content,
    )
    .map(Buffer::from)
    .map_err(napi_error)
}

#[napi(string_enum)]
pub enum CmsSignerStatusCode {
    Unsigned,
    Valid,
    NeedsDetachedContent,
    InvalidSignature,
    InvalidCertificate,
    InvalidIndex,
}

fn signer_status(value: CMSSignerStatus) -> CmsSignerStatusCode {
    match value {
        CMSSignerStatus::kCMSSignerUnsigned => CmsSignerStatusCode::Unsigned,
        CMSSignerStatus::kCMSSignerValid => CmsSignerStatusCode::Valid,
        CMSSignerStatus::kCMSSignerNeedsDetachedContent => {
            CmsSignerStatusCode::NeedsDetachedContent
        }
        CMSSignerStatus::kCMSSignerInvalidSignature => CmsSignerStatusCode::InvalidSignature,
        CMSSignerStatus::kCMSSignerInvalidCert => CmsSignerStatusCode::InvalidCertificate,
        CMSSignerStatus::kCMSSignerInvalidIndex => CmsSignerStatusCode::InvalidIndex,
    }
}

#[napi(object, object_from_js = false)]
pub struct CmsSignerStatus {
    pub status: CmsSignerStatusCode,
    pub trust: SecTrust,
    pub certificate_valid: bool,
    pub certificate_error: Option<String>,
}

#[napi]
pub struct CmsDecoder {
    inner: NativeCmsDecoder,
}

#[napi]
impl CmsDecoder {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        NativeCmsDecoder::create()
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn update(&self, message: Buffer) -> Result<()> {
        self.inner.update_message(&message).map_err(napi_error)
    }

    #[napi]
    pub fn finalize(&self) -> Result<()> {
        self.inner.finalize_message().map_err(napi_error)
    }

    #[napi]
    pub fn set_detached_content(&self, content: Buffer) -> Result<()> {
        self.inner
            .set_detached_content(&content)
            .map_err(napi_error)
    }

    #[napi]
    pub fn detached_content(&self) -> Result<Buffer> {
        self.inner
            .get_detached_content()
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn num_signers(&self) -> Result<u32> {
        self.inner
            .get_num_signers()
            .map(|value| value as u32)
            .map_err(napi_error)
    }

    #[napi]
    pub fn signer_status(
        &self,
        signer_index: u32,
        policies: Vec<ClassInstance<'_, SecPolicy>>,
    ) -> Result<CmsSignerStatus> {
        let policies = policies
            .iter()
            .map(|policy| policy.inner.clone())
            .collect::<Vec<_>>();
        let result = self
            .inner
            .get_signer_status(signer_index as usize, &policies)
            .map_err(napi_error)?;
        let certificate_error = result
            .cert_verify_result
            .err()
            .map(|error| error.to_string());
        Ok(CmsSignerStatus {
            status: signer_status(result.signer_status),
            trust: SecTrust {
                inner: result.sec_trust,
            },
            certificate_valid: certificate_error.is_none(),
            certificate_error,
        })
    }

    #[napi]
    pub fn signer_email(&self, signer_index: u32) -> Result<String> {
        self.inner
            .get_signer_email_address(signer_index as usize)
            .map_err(napi_error)
    }

    #[napi]
    pub fn is_encrypted(&self) -> Result<bool> {
        self.inner.is_content_encrypted().map_err(napi_error)
    }

    #[napi]
    pub fn content_type(&self) -> Result<Buffer> {
        self.inner
            .get_encapsulated_content_type()
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn all_certificates(&self) -> Result<Vec<SecCertificate>> {
        self.inner
            .get_all_certs()
            .map(|values| {
                values
                    .into_iter()
                    .map(|inner| SecCertificate { inner })
                    .collect()
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn content(&self) -> Result<Buffer> {
        self.inner
            .get_content()
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn signing_time(&self, signer_index: u32) -> Result<f64> {
        self.inner
            .get_signer_signing_time(signer_index as usize)
            .map(timestamp_ms)
            .map_err(napi_error)
    }

    #[napi]
    pub fn signer_timestamp(&self, signer_index: u32) -> Result<f64> {
        self.inner
            .get_signer_timestamp(signer_index as usize)
            .map(timestamp_ms)
            .map_err(napi_error)
    }

    #[napi]
    pub fn signer_timestamp_with_policy(
        &self,
        policy: Option<String>,
        signer_index: u32,
    ) -> Result<f64> {
        let policy = policy.map(|value| CFString::new(&value));
        self.inner
            .get_signer_timestamp_with_policy(
                policy.as_ref().map(|value| value.as_concrete_TypeRef()),
                signer_index as usize,
            )
            .map(timestamp_ms)
            .map_err(napi_error)
    }

    #[napi]
    pub fn timestamp_certificates(&self, signer_index: u32) -> Result<Vec<SecCertificate>> {
        self.inner
            .get_signer_timestamp_certificates(signer_index as usize)
            .map(|values| {
                values
                    .into_iter()
                    .map(|inner| SecCertificate { inner })
                    .collect()
            })
            .map_err(napi_error)
    }
}
