use core_foundation::data::CFData;
use napi::bindgen_prelude::{Buffer, Result};
use napi_derive::napi;
use security_framework::os::macos::digest_transform::{
    Builder as NativeDigestBuilder, DigestType as NativeDigestType,
};
use security_framework::os::macos::encrypt_transform::{
    Builder as NativeEncryptBuilder, Mode as NativeMode, Padding as NativePadding,
};

use super::error::napi_error;
use super::security::SecKey;

#[napi(string_enum)]
pub enum DigestType {
    HmacMd5,
    HmacSha1,
    HmacSha2,
    Md2,
    Md4,
    Md5,
    Sha1,
    Sha2,
}

impl From<DigestType> for NativeDigestType {
    fn from(value: DigestType) -> Self {
        match value {
            DigestType::HmacMd5 => Self::hmac_md5(),
            DigestType::HmacSha1 => Self::hmac_sha1(),
            DigestType::HmacSha2 => Self::hmac_sha2(),
            DigestType::Md2 => Self::md2(),
            DigestType::Md4 => Self::md4(),
            DigestType::Md5 => Self::md5(),
            DigestType::Sha1 => Self::sha1(),
            DigestType::Sha2 => Self::sha2(),
        }
    }
}

#[napi]
pub struct DigestBuilder {
    inner: NativeDigestBuilder,
}

impl Default for DigestBuilder {
    fn default() -> Self {
        Self {
            inner: NativeDigestBuilder::new(),
        }
    }
}

#[napi]
impl DigestBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn digest_type(&mut self, digest_type: DigestType) -> &Self {
        self.inner.type_(digest_type.into());
        self
    }

    #[napi]
    pub fn length(&mut self, length: i64) -> &Self {
        self.inner.length(length as isize);
        self
    }

    #[napi]
    pub fn hmac_key(&mut self, key: Buffer) -> &Self {
        self.inner.hmac_key(CFData::from_buffer(&key));
        self
    }

    #[napi]
    pub fn execute(&self, data: Buffer) -> Result<Buffer> {
        self.inner
            .execute(&CFData::from_buffer(&data))
            .map(|data| data.bytes().to_vec().into())
            .map_err(napi_error)
    }
}

#[napi(string_enum)]
pub enum Padding {
    None,
    Pkcs1,
    Pkcs5,
    Pkcs7,
    Oaep,
}

impl From<Padding> for NativePadding {
    fn from(value: Padding) -> Self {
        match value {
            Padding::None => Self::none(),
            Padding::Pkcs1 => Self::pkcs1(),
            Padding::Pkcs5 => Self::pkcs5(),
            Padding::Pkcs7 => Self::pkcs7(),
            Padding::Oaep => Self::oaep(),
        }
    }
}

#[napi(string_enum)]
pub enum EncryptionMode {
    None,
    Ecb,
    Cbc,
    Cfb,
    Ofb,
}

impl From<EncryptionMode> for NativeMode {
    fn from(value: EncryptionMode) -> Self {
        match value {
            EncryptionMode::None => Self::none(),
            EncryptionMode::Ecb => Self::ecb(),
            EncryptionMode::Cbc => Self::cbc(),
            EncryptionMode::Cfb => Self::cfb(),
            EncryptionMode::Ofb => Self::ofb(),
        }
    }
}

#[napi]
pub struct EncryptBuilder {
    inner: NativeEncryptBuilder,
}

impl Default for EncryptBuilder {
    fn default() -> Self {
        Self {
            inner: NativeEncryptBuilder::new(),
        }
    }
}

#[napi]
impl EncryptBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn padding(&mut self, padding: Padding) -> &Self {
        self.inner.padding(padding.into());
        self
    }

    #[napi]
    pub fn mode(&mut self, mode: EncryptionMode) -> &Self {
        self.inner.mode(mode.into());
        self
    }

    #[napi]
    pub fn iv(&mut self, iv: Buffer) -> &Self {
        self.inner.iv(CFData::from_buffer(&iv));
        self
    }

    #[napi]
    pub fn encrypt(&self, key: &SecKey, data: Buffer) -> Result<Buffer> {
        self.inner
            .encrypt(&key.inner, &CFData::from_buffer(&data))
            .map(|data| data.bytes().to_vec().into())
            .map_err(napi_error)
    }

    #[napi]
    pub fn decrypt(&self, key: &SecKey, data: Buffer) -> Result<Buffer> {
        self.inner
            .decrypt(&key.inner, &CFData::from_buffer(&data))
            .map(|data| data.bytes().to_vec().into())
            .map_err(napi_error)
    }
}
