use napi::bindgen_prelude::{Buffer, Result};
use napi_derive::napi;
use security_framework::import_export::Pkcs12ImportOptions as NativePkcs12ImportOptions;
use security_framework::os::macos::import_export::{
    ImportOptions as NativeImportOptions, SecItems as NativeSecItems,
};
use security_framework::os::macos::keychain::SecKeychain as NativeSecKeychain;

use super::error::napi_error;
use super::keychain::SecKeychain;
use super::security::{SecCertificate, SecIdentity, SecKey, SecTrust};

#[napi(object, object_from_js = false)]
pub struct ImportedIdentity {
    pub label: Option<String>,
    pub key_id: Option<Buffer>,
    pub trust: Option<SecTrust>,
    pub certificate_chain: Option<Vec<SecCertificate>>,
    pub identity: Option<SecIdentity>,
}

#[napi]
pub struct Pkcs12ImportOptions {
    inner: NativePkcs12ImportOptions,
}

impl Default for Pkcs12ImportOptions {
    fn default() -> Self {
        Self {
            inner: NativePkcs12ImportOptions::new(),
        }
    }
}

#[napi]
impl Pkcs12ImportOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn passphrase(&mut self, passphrase: String) -> &Self {
        self.inner.passphrase(&passphrase);
        self
    }

    #[napi]
    pub fn keychain(&mut self, keychain: &SecKeychain) -> &Self {
        self.inner.keychain(keychain.inner.clone());
        self
    }

    #[napi]
    pub fn import(&self, data: Buffer) -> Result<Vec<ImportedIdentity>> {
        self.inner
            .import(&data)
            .map(|identities| {
                identities
                    .into_iter()
                    .map(|value| ImportedIdentity {
                        label: value.label,
                        key_id: value.key_id.map(Buffer::from),
                        trust: value.trust.map(|inner| SecTrust { inner }),
                        certificate_chain: value.cert_chain.map(|certificates| {
                            certificates
                                .into_iter()
                                .map(|inner| SecCertificate { inner })
                                .collect()
                        }),
                        identity: value.identity.map(|inner| SecIdentity { inner }),
                    })
                    .collect()
            })
            .map_err(napi_error)
    }
}

enum Passphrase {
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Default)]
#[napi]
pub struct ImportOptions {
    filename: Option<String>,
    pkcs12: bool,
    passphrase: Option<Passphrase>,
    secure_passphrase: bool,
    no_access_control: bool,
    alert_title: Option<String>,
    alert_prompt: Option<String>,
    keychain: Option<NativeSecKeychain>,
}

#[napi]
impl ImportOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn filename(&mut self, filename: String) -> &Self {
        self.filename = Some(filename);
        self
    }

    #[napi]
    pub fn pkcs12(&mut self) -> &Self {
        self.pkcs12 = true;
        self
    }

    #[napi]
    pub fn passphrase(&mut self, passphrase: String) -> &Self {
        self.passphrase = Some(Passphrase::Text(passphrase));
        self
    }

    #[napi]
    pub fn passphrase_bytes(&mut self, passphrase: Buffer) -> &Self {
        self.passphrase = Some(Passphrase::Bytes(passphrase.to_vec()));
        self
    }

    #[napi]
    pub fn secure_passphrase(&mut self, secure_passphrase: bool) -> &Self {
        self.secure_passphrase = secure_passphrase;
        self
    }

    #[napi]
    pub fn no_access_control(&mut self, no_access_control: bool) -> &Self {
        self.no_access_control = no_access_control;
        self
    }

    #[napi]
    pub fn alert_title(&mut self, alert_title: String) -> &Self {
        self.alert_title = Some(alert_title);
        self
    }

    #[napi]
    pub fn alert_prompt(&mut self, alert_prompt: String) -> &Self {
        self.alert_prompt = Some(alert_prompt);
        self
    }

    #[napi]
    pub fn keychain(&mut self, keychain: &SecKeychain) -> &Self {
        self.keychain = Some(keychain.inner.clone());
        self
    }

    #[napi]
    pub fn import(&self, data: Buffer) -> Result<ImportedItems> {
        let mut items = NativeSecItems::default();
        let mut options = NativeImportOptions::new();

        if let Some(filename) = &self.filename {
            options.filename(filename);
        }
        if self.pkcs12 {
            options.pkcs12();
        }
        match &self.passphrase {
            Some(Passphrase::Text(passphrase)) => {
                options.passphrase(passphrase);
            }
            Some(Passphrase::Bytes(passphrase)) => {
                options.passphrase_bytes(passphrase);
            }
            None => {}
        }
        options
            .secure_passphrase(self.secure_passphrase)
            .no_access_control(self.no_access_control);
        if let Some(alert_title) = &self.alert_title {
            options.alert_title(alert_title);
        }
        if let Some(alert_prompt) = &self.alert_prompt {
            options.alert_prompt(alert_prompt);
        }
        if let Some(keychain) = &self.keychain {
            options.keychain(keychain);
        }

        options
            .items(&mut items)
            .import(&data)
            .map_err(napi_error)?;

        Ok(ImportedItems {
            certificates: items
                .certificates
                .into_iter()
                .map(|inner| SecCertificate { inner })
                .collect(),
            identities: items
                .identities
                .into_iter()
                .map(|inner| SecIdentity { inner })
                .collect(),
            keys: items
                .keys
                .into_iter()
                .map(|inner| SecKey { inner })
                .collect(),
        })
    }
}

#[napi(object, object_from_js = false)]
pub struct ImportedItems {
    pub certificates: Vec<SecCertificate>,
    pub identities: Vec<SecIdentity>,
    pub keys: Vec<SecKey>,
}
