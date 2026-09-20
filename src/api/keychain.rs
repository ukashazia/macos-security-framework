use napi::bindgen_prelude::{Buffer, ClassInstance, Result};
use napi_derive::napi;
use security_framework::os::macos::keychain::{
    CreateOptions as NativeCreateOptions, KeychainSettings as NativeKeychainSettings,
    KeychainUserInteractionLock as NativeKeychainUserInteractionLock,
    SecKeychain as NativeSecKeychain,
};
use security_framework::os::macos::passwords::{
    find_generic_password as native_find_generic_password,
    find_internet_password as native_find_internet_password,
};
use security_framework_sys::keychain::SecPreferencesDomain;

use super::error::napi_error;
use super::items::SecKeychainItem;
use super::passwords::{AuthenticationType, Protocol};

#[napi(object, object_from_js = false)]
pub struct KeychainPassword {
    pub password: Buffer,
    pub item: SecKeychainItem,
}

#[napi]
pub enum KeychainDomain {
    User,
    System,
    Common,
    Dynamic,
}

impl From<KeychainDomain> for SecPreferencesDomain {
    fn from(value: KeychainDomain) -> Self {
        match value {
            KeychainDomain::User => Self::User,
            KeychainDomain::System => Self::System,
            KeychainDomain::Common => Self::Common,
            KeychainDomain::Dynamic => Self::Dynamic,
        }
    }
}

#[napi]
pub struct SecKeychain {
    pub(crate) inner: NativeSecKeychain,
}

#[napi]
impl SecKeychain {
    #[napi(factory)]
    pub fn default_keychain() -> Result<Self> {
        NativeSecKeychain::default()
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn default_for_domain(domain: KeychainDomain) -> Result<Self> {
        NativeSecKeychain::default_for_domain(domain.into())
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi(factory)]
    pub fn open(path: String) -> Result<Self> {
        NativeSecKeychain::open(path)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn unlock(&mut self, password: Option<String>) -> Result<()> {
        self.inner.unlock(password.as_deref()).map_err(napi_error)
    }

    #[napi]
    pub fn set_settings(&mut self, settings: &KeychainSettings) -> Result<()> {
        self.inner.set_settings(&settings.inner).map_err(napi_error)
    }

    #[napi]
    pub fn user_interaction_allowed() -> Result<bool> {
        NativeSecKeychain::user_interaction_allowed().map_err(napi_error)
    }

    #[napi]
    pub fn disable_user_interaction() -> Result<KeychainUserInteractionLock> {
        NativeSecKeychain::disable_user_interaction()
            .map(|inner| KeychainUserInteractionLock { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub fn find_generic_password(
        &self,
        service: String,
        account: String,
    ) -> Result<KeychainPassword> {
        self.inner
            .find_generic_password(&service, &account)
            .map(|(password, item)| KeychainPassword {
                password: password.as_ref().to_vec().into(),
                item: SecKeychainItem { inner: Some(item) },
            })
            .map_err(napi_error)
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn find_internet_password(
        &self,
        server: String,
        security_domain: Option<String>,
        account: String,
        path: String,
        port: Option<u16>,
        protocol: Protocol,
        authentication_type: AuthenticationType,
    ) -> Result<KeychainPassword> {
        self.inner
            .find_internet_password(
                &server,
                security_domain.as_deref(),
                &account,
                &path,
                port,
                protocol.into(),
                authentication_type.into(),
            )
            .map(|(password, item)| KeychainPassword {
                password: password.as_ref().to_vec().into(),
                item: SecKeychainItem { inner: Some(item) },
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_generic_password(
        &self,
        service: String,
        account: String,
        password: Buffer,
    ) -> Result<()> {
        self.inner
            .set_generic_password(&service, &account, &password)
            .map_err(napi_error)
    }

    #[napi]
    pub fn add_generic_password(
        &self,
        service: String,
        account: String,
        password: Buffer,
    ) -> Result<()> {
        self.inner
            .add_generic_password(&service, &account, &password)
            .map_err(napi_error)
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn set_internet_password(
        &self,
        server: String,
        security_domain: Option<String>,
        account: String,
        path: String,
        port: Option<u16>,
        protocol: Protocol,
        authentication_type: AuthenticationType,
        password: Buffer,
    ) -> Result<()> {
        self.inner
            .set_internet_password(
                &server,
                security_domain.as_deref(),
                &account,
                &path,
                port,
                protocol.into(),
                authentication_type.into(),
                &password,
            )
            .map_err(napi_error)
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn add_internet_password(
        &self,
        server: String,
        security_domain: Option<String>,
        account: String,
        path: String,
        port: Option<u16>,
        protocol: Protocol,
        authentication_type: AuthenticationType,
        password: Buffer,
    ) -> Result<()> {
        self.inner
            .add_internet_password(
                &server,
                security_domain.as_deref(),
                &account,
                &path,
                port,
                protocol.into(),
                authentication_type.into(),
                &password,
            )
            .map_err(napi_error)
    }
}

#[napi]
pub fn find_generic_password(
    keychains: Option<Vec<ClassInstance<'_, SecKeychain>>>,
    service: String,
    account: String,
) -> Result<KeychainPassword> {
    let keychains = keychains.map(|values| {
        values
            .iter()
            .map(|keychain| keychain.inner.clone())
            .collect::<Vec<_>>()
    });
    native_find_generic_password(keychains.as_deref(), &service, &account)
        .map(|(password, item)| KeychainPassword {
            password: password.as_ref().to_vec().into(),
            item: SecKeychainItem { inner: Some(item) },
        })
        .map_err(napi_error)
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn find_internet_password(
    keychains: Option<Vec<ClassInstance<'_, SecKeychain>>>,
    server: String,
    security_domain: Option<String>,
    account: String,
    path: String,
    port: Option<u16>,
    protocol: Protocol,
    authentication_type: AuthenticationType,
) -> Result<KeychainPassword> {
    let keychains = keychains.map(|values| {
        values
            .iter()
            .map(|keychain| keychain.inner.clone())
            .collect::<Vec<_>>()
    });
    native_find_internet_password(
        keychains.as_deref(),
        &server,
        security_domain.as_deref(),
        &account,
        &path,
        port,
        protocol.into(),
        authentication_type.into(),
    )
    .map(|(password, item)| KeychainPassword {
        password: password.as_ref().to_vec().into(),
        item: SecKeychainItem { inner: Some(item) },
    })
    .map_err(napi_error)
}

#[napi]
pub struct KeychainCreateOptions {
    inner: NativeCreateOptions,
}

impl Default for KeychainCreateOptions {
    fn default() -> Self {
        Self {
            inner: NativeCreateOptions::new(),
        }
    }
}

#[napi]
impl KeychainCreateOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn password(&mut self, password: String) -> &Self {
        self.inner.password(&password);
        self
    }

    #[napi]
    pub fn prompt_user(&mut self, prompt_user: bool) -> &Self {
        self.inner.prompt_user(prompt_user);
        self
    }

    #[napi]
    pub fn create(&self, path: String) -> Result<SecKeychain> {
        self.inner
            .create(path)
            .map(|inner| SecKeychain { inner })
            .map_err(napi_error)
    }
}

#[napi]
pub struct KeychainSettings {
    inner: NativeKeychainSettings,
}

impl Default for KeychainSettings {
    fn default() -> Self {
        Self {
            inner: NativeKeychainSettings::new(),
        }
    }
}

#[napi]
impl KeychainSettings {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn set_lock_on_sleep(&mut self, lock_on_sleep: bool) -> &Self {
        self.inner.set_lock_on_sleep(lock_on_sleep);
        self
    }

    #[napi]
    pub fn set_lock_interval(&mut self, lock_interval: Option<u32>) -> &Self {
        self.inner.set_lock_interval(lock_interval);
        self
    }
}

#[napi]
pub struct KeychainUserInteractionLock {
    inner: Option<NativeKeychainUserInteractionLock>,
}

#[napi]
impl KeychainUserInteractionLock {
    #[napi]
    pub fn release(&mut self) {
        self.inner.take();
    }
}
