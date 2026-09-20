use std::ffi::c_char;
use std::io::Read;
use std::str::FromStr;

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use napi::bindgen_prelude::{Buffer, Result};
use napi::{Error, Status};
use napi_derive::napi;
use security_framework::authorization::{
    Authorization as NativeAuthorization, AuthorizationItemSetBuilder, Flags as AuthorizationFlags,
    RightDefinition,
};
use security_framework::os::macos::code_signing::{
    Flags as CodeSigningFlags, GuestAttributes as NativeGuestAttributes, SecCode as NativeSecCode,
    SecRequirement as NativeSecRequirement, SecStaticCode as NativeSecStaticCode,
};
use security_framework::trust_settings::{
    Domain as NativeTrustSettingsDomain, TrustSettings as NativeTrustSettings,
    TrustSettingsForCertificate as NativeTrustSettingsForCertificate,
};
use security_framework_sys::authorization::AuthorizationExternalForm;

use super::error::napi_error;
use super::security::SecCertificate;

#[napi(string_enum)]
pub enum TrustSettingsDomain {
    User,
    Admin,
    System,
}

impl From<TrustSettingsDomain> for NativeTrustSettingsDomain {
    fn from(value: TrustSettingsDomain) -> Self {
        match value {
            TrustSettingsDomain::User => Self::User,
            TrustSettingsDomain::Admin => Self::Admin,
            TrustSettingsDomain::System => Self::System,
        }
    }
}

#[napi(string_enum)]
pub enum CertificateTrustSetting {
    Invalid,
    TrustRoot,
    TrustAsRoot,
    Deny,
    Unspecified,
}

impl From<NativeTrustSettingsForCertificate> for CertificateTrustSetting {
    fn from(value: NativeTrustSettingsForCertificate) -> Self {
        match value {
            NativeTrustSettingsForCertificate::Invalid => Self::Invalid,
            NativeTrustSettingsForCertificate::TrustRoot => Self::TrustRoot,
            NativeTrustSettingsForCertificate::TrustAsRoot => Self::TrustAsRoot,
            NativeTrustSettingsForCertificate::Deny => Self::Deny,
            NativeTrustSettingsForCertificate::Unspecified => Self::Unspecified,
        }
    }
}

#[napi]
pub struct TrustSettings {
    inner: NativeTrustSettings,
}

#[napi]
impl TrustSettings {
    #[napi(constructor)]
    pub fn new(domain: TrustSettingsDomain) -> Self {
        Self {
            inner: NativeTrustSettings::new(domain.into()),
        }
    }

    #[napi]
    pub fn certificates(&self) -> Result<Vec<SecCertificate>> {
        self.inner
            .iter()
            .map(|values| {
                values
                    .map(|inner| SecCertificate { inner })
                    .collect::<Vec<_>>()
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_always(&self, certificate: &SecCertificate) -> Result<()> {
        self.inner
            .set_trust_settings_always(&certificate.inner)
            .map_err(napi_error)
    }

    #[napi]
    pub fn for_certificate(
        &self,
        certificate: &SecCertificate,
    ) -> Result<Option<CertificateTrustSetting>> {
        self.inner
            .tls_trust_settings_for_certificate(&certificate.inner)
            .map(|value| value.map(CertificateTrustSetting::from))
            .map_err(napi_error)
    }
}

#[napi]
pub struct GuestAttributes {
    inner: NativeGuestAttributes,
}

impl Default for GuestAttributes {
    fn default() -> Self {
        Self {
            inner: NativeGuestAttributes::new(),
        }
    }
}

#[napi]
impl GuestAttributes {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn set_pid(&mut self, pid: i32) -> &Self {
        self.inner.set_pid(pid as libc::pid_t);
        self
    }

    #[napi]
    pub fn set_audit_token(&mut self, token: Buffer) -> &Self {
        let token = CFData::from_buffer(&token);
        self.inner.set_audit_token(token.as_concrete_TypeRef());
        self
    }

    #[napi]
    pub fn set_other(&mut self, key: String, value: String) -> &Self {
        let key = CFString::new(&key);
        let value = CFString::new(&value);
        self.inner.set_other(key.as_concrete_TypeRef(), value);
        self
    }
}

#[napi]
pub struct SecRequirement {
    inner: NativeSecRequirement,
}

#[napi]
impl SecRequirement {
    #[napi(factory)]
    pub fn parse(requirement: String) -> Result<Self> {
        NativeSecRequirement::from_str(&requirement)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }
}

#[napi]
pub struct SecCode {
    inner: NativeSecCode,
}

#[napi]
impl SecCode {
    #[napi(factory)]
    pub fn for_self(flags: u32) -> Result<Self> {
        NativeSecCode::for_self(CodeSigningFlags::from_bits_retain(flags))
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn guest(host: Option<&SecCode>, attributes: &GuestAttributes, flags: u32) -> Result<Self> {
        NativeSecCode::copy_guest_with_attribues(
            host.map(|value| &value.inner),
            &attributes.inner,
            CodeSigningFlags::from_bits_retain(flags),
        )
        .map(|inner| Self { inner })
        .map_err(napi_error)
    }

    #[napi]
    pub fn check_validity(&self, flags: u32, requirement: &SecRequirement) -> Result<()> {
        self.inner
            .check_validity(
                CodeSigningFlags::from_bits_retain(flags),
                &requirement.inner,
            )
            .map_err(napi_error)
    }

    #[napi]
    pub fn path(&self, flags: u32) -> Result<String> {
        self.inner
            .path(CodeSigningFlags::from_bits_retain(flags))
            .map_err(napi_error)?
            .to_path()
            .map(|path| path.to_string_lossy().into_owned())
            .ok_or_else(|| Error::new(Status::GenericFailure, "code URL is not a file path"))
    }
}

#[napi]
pub struct SecStaticCode {
    inner: NativeSecStaticCode,
}

#[napi]
impl SecStaticCode {
    #[napi(factory)]
    pub fn from_path(path: String, flags: u32) -> Result<Self> {
        let url = CFURL::from_path(path, false)
            .ok_or_else(|| Error::new(Status::InvalidArg, "invalid file path"))?;
        NativeSecStaticCode::from_path(&url, CodeSigningFlags::from_bits_retain(flags))
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn check_validity(&self, flags: u32, requirement: &SecRequirement) -> Result<()> {
        self.inner
            .check_validity(
                CodeSigningFlags::from_bits_retain(flags),
                &requirement.inner,
            )
            .map_err(napi_error)
    }

    #[napi]
    pub fn path(&self, flags: u32) -> Result<String> {
        self.inner
            .path(CodeSigningFlags::from_bits_retain(flags))
            .map_err(napi_error)?
            .to_path()
            .map(|path| path.to_string_lossy().into_owned())
            .ok_or_else(|| Error::new(Status::GenericFailure, "code URL is not a file path"))
    }
}

#[napi(object)]
pub struct AuthorizationItem {
    pub name: String,
    pub data: Option<Buffer>,
    pub text: Option<String>,
}

fn authorization_items(
    items: Option<Vec<AuthorizationItem>>,
) -> Result<Option<security_framework::authorization::AuthorizationItemSetStorage>> {
    let Some(items) = items else {
        return Ok(None);
    };

    let mut builder = AuthorizationItemSetBuilder::new();
    for item in items {
        builder = if let Some(data) = item.data {
            builder.add_data(item.name, data.to_vec())
        } else if let Some(text) = item.text {
            builder.add_string(item.name, text)
        } else {
            builder.add_right(item.name)
        }
        .map_err(napi_error)?;
    }
    Ok(Some(builder.build()))
}

#[napi]
pub struct Authorization {
    inner: Option<NativeAuthorization>,
}

impl Authorization {
    fn inner(&self) -> Result<&NativeAuthorization> {
        self.inner.as_ref().ok_or_else(|| {
            Error::new(
                Status::InvalidArg,
                "authorization rights have been destroyed".to_owned(),
            )
        })
    }
}

#[napi]
impl Authorization {
    #[napi(constructor)]
    pub fn new(
        rights: Option<Vec<AuthorizationItem>>,
        environment: Option<Vec<AuthorizationItem>>,
        flags: u32,
    ) -> Result<Self> {
        NativeAuthorization::new(
            authorization_items(rights)?,
            authorization_items(environment)?,
            AuthorizationFlags::from_bits_retain(flags),
        )
        .map(|inner| Self { inner: Some(inner) })
        .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn default_authorization() -> Result<Self> {
        NativeAuthorization::default()
            .map(|inner| Self { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn from_external_form(data: Buffer) -> Result<Self> {
        let bytes: [u8; 32] = data.as_ref().try_into().map_err(|_| {
            Error::new(
                Status::InvalidArg,
                "authorization external form must be exactly 32 bytes",
            )
        })?;
        let form = AuthorizationExternalForm {
            bytes: bytes.map(|byte| byte as c_char),
        };
        NativeAuthorization::try_from(form)
            .map(|inner| Self { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub fn destroy_rights(&mut self) {
        if let Some(authorization) = self.inner.take() {
            authorization.destroy_rights();
        }
    }

    #[napi]
    pub fn right_exists(name: String) -> Result<bool> {
        NativeAuthorization::right_exists(name).map_err(napi_error)
    }

    #[napi]
    pub fn get_right(name: String) -> Result<String> {
        NativeAuthorization::get_right(name)
            .map(|value| format!("{value:?}"))
            .map_err(napi_error)
    }

    #[napi]
    pub fn remove_right(&self, name: String) -> Result<()> {
        self.inner()?.remove_right(name).map_err(napi_error)
    }

    #[napi]
    pub fn set_right(
        &self,
        name: String,
        existing_right: String,
        description: Option<String>,
        locale: Option<String>,
    ) -> Result<()> {
        self.inner()?
            .set_right(
                name,
                RightDefinition::FromExistingRight(&existing_right),
                description.as_deref(),
                None,
                locale.as_deref(),
            )
            .map_err(napi_error)
    }

    #[napi]
    pub fn copy_info(&self, tag: Option<String>) -> Result<String> {
        self.inner()?
            .copy_info(tag)
            .map(|value| format!("{value:?}"))
            .map_err(napi_error)
    }

    #[napi]
    pub fn make_external_form(&self) -> Result<Buffer> {
        self.inner()?
            .make_external_form()
            .map(|form| form.bytes.map(|byte| byte as u8).to_vec().into())
            .map_err(napi_error)
    }

    #[napi]
    pub fn execute(&self, command: String, arguments: Vec<String>, flags: u32) -> Result<()> {
        self.inner()?
            .execute_with_privileges(
                command,
                arguments,
                AuthorizationFlags::from_bits_retain(flags),
            )
            .map_err(napi_error)
    }

    #[napi]
    pub fn execute_piped(
        &self,
        command: String,
        arguments: Vec<String>,
        flags: u32,
    ) -> Result<Buffer> {
        let mut output = Vec::new();
        self.inner()?
            .execute_with_privileges_piped(
                command,
                arguments,
                AuthorizationFlags::from_bits_retain(flags),
            )
            .map_err(napi_error)?
            .read_to_end(&mut output)
            .map_err(napi_error)?;
        Ok(output.into())
    }

    #[napi]
    pub fn job_bless(&self, label: String) -> Result<()> {
        self.inner()?.job_bless(&label).map_err(napi_error)
    }
}
