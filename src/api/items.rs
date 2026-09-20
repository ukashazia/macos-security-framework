use std::collections::HashMap;

use core_foundation::data::CFData;
use napi::bindgen_prelude::{Buffer, ClassInstance, Result};
use napi_derive::napi;
use security_framework::item::{
    AddRef, CloudSync as NativeCloudSync, ItemAddOptions as NativeItemAddOptions, ItemAddValue,
    ItemClass as NativeItemClass, ItemSearchOptions as NativeItemSearchOptions,
    ItemUpdateOptions as NativeItemUpdateOptions, ItemUpdateValue, KeyClass as NativeKeyClass,
    Limit, Location, Reference, SearchResult, update_item as native_update_item,
};
use security_framework::os::macos::keychain_item::SecKeychainItem as NativeSecKeychainItem;

use super::error::napi_error;
use super::keychain::SecKeychain;
use super::security::{SecCertificate, SecIdentity, SecKey};

#[napi(string_enum)]
pub enum ItemClass {
    GenericPassword,
    InternetPassword,
    Certificate,
    Key,
    Identity,
}

impl From<ItemClass> for NativeItemClass {
    fn from(value: ItemClass) -> Self {
        match value {
            ItemClass::GenericPassword => Self::generic_password(),
            ItemClass::InternetPassword => Self::internet_password(),
            ItemClass::Certificate => Self::certificate(),
            ItemClass::Key => Self::key(),
            ItemClass::Identity => Self::identity(),
        }
    }
}

#[napi(string_enum)]
pub enum KeyClass {
    Public,
    Private,
    Symmetric,
}

impl From<KeyClass> for NativeKeyClass {
    fn from(value: KeyClass) -> Self {
        match value {
            KeyClass::Public => Self::public(),
            KeyClass::Private => Self::private(),
            KeyClass::Symmetric => Self::symmetric(),
        }
    }
}

#[napi(string_enum)]
pub enum CloudSync {
    Yes,
    No,
    Any,
}

impl From<CloudSync> for NativeCloudSync {
    fn from(value: CloudSync) -> Self {
        match value {
            CloudSync::Yes => Self::MatchSyncYes,
            CloudSync::No => Self::MatchSyncNo,
            CloudSync::Any => Self::MatchSyncAny,
        }
    }
}

#[napi(object, object_from_js = false)]
pub struct ItemSearchResult {
    pub kind: String,
    pub data: Option<Buffer>,
    pub attributes: Option<HashMap<String, String>>,
    pub certificate: Option<SecCertificate>,
    pub key: Option<SecKey>,
    pub identity: Option<SecIdentity>,
    pub keychain_item: Option<SecKeychainItem>,
}

impl ItemSearchResult {
    fn empty(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            data: None,
            attributes: None,
            certificate: None,
            key: None,
            identity: None,
            keychain_item: None,
        }
    }
}

fn search_result(value: SearchResult) -> ItemSearchResult {
    match value {
        SearchResult::Data(data) => ItemSearchResult {
            data: Some(data.into()),
            ..ItemSearchResult::empty("data")
        },
        value @ SearchResult::Dict(_) => ItemSearchResult {
            attributes: value.simplify_dict(),
            ..ItemSearchResult::empty("attributes")
        },
        SearchResult::Ref(reference) => match reference {
            Reference::Certificate(inner) => ItemSearchResult {
                certificate: Some(SecCertificate { inner }),
                ..ItemSearchResult::empty("certificate")
            },
            Reference::Key(inner) => ItemSearchResult {
                key: Some(SecKey { inner }),
                ..ItemSearchResult::empty("key")
            },
            Reference::Identity(inner) => ItemSearchResult {
                identity: Some(SecIdentity { inner }),
                ..ItemSearchResult::empty("identity")
            },
            Reference::KeychainItem(inner) => ItemSearchResult {
                keychain_item: Some(SecKeychainItem { inner: Some(inner) }),
                ..ItemSearchResult::empty("keychainItem")
            },
            _ => ItemSearchResult::empty("unknown"),
        },
        SearchResult::Other => ItemSearchResult::empty("unknown"),
    }
}

#[napi]
pub struct ItemSearchOptions {
    inner: NativeItemSearchOptions,
}

impl Default for ItemSearchOptions {
    fn default() -> Self {
        Self {
            inner: NativeItemSearchOptions::new(),
        }
    }
}

#[napi]
impl ItemSearchOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn keychains(&mut self, keychains: Vec<ClassInstance<'_, SecKeychain>>) -> &Self {
        let keychains = keychains
            .iter()
            .map(|keychain| keychain.inner.clone())
            .collect::<Vec<_>>();
        self.inner.keychains(&keychains);
        self
    }

    #[napi]
    pub fn ignore_legacy_keychains(&mut self) -> &Self {
        self.inner.ignore_legacy_keychains();
        self
    }

    #[napi]
    pub fn class(&mut self, item_class: ItemClass) -> &Self {
        self.inner.class(item_class.into());
        self
    }

    #[napi]
    pub fn case_insensitive(&mut self, case_insensitive: Option<bool>) -> &Self {
        self.inner.case_insensitive(case_insensitive);
        self
    }

    #[napi]
    pub fn key_class(&mut self, key_class: KeyClass) -> &Self {
        self.inner.key_class(key_class.into());
        self
    }

    #[napi]
    pub fn load_refs(&mut self, load_refs: bool) -> &Self {
        self.inner.load_refs(load_refs);
        self
    }

    #[napi]
    pub fn load_attributes(&mut self, load_attributes: bool) -> &Self {
        self.inner.load_attributes(load_attributes);
        self
    }

    #[napi]
    pub fn load_data(&mut self, load_data: bool) -> &Self {
        self.inner.load_data(load_data);
        self
    }

    #[napi]
    pub fn limit_all(&mut self) -> &Self {
        self.inner.limit(Limit::All);
        self
    }

    #[napi]
    pub fn limit(&mut self, limit: i64) -> &Self {
        self.inner.limit(limit);
        self
    }

    #[napi]
    pub fn label(&mut self, label: String) -> &Self {
        self.inner.label(&label);
        self
    }

    #[napi]
    pub fn trusted_only(&mut self, trusted_only: Option<bool>) -> &Self {
        self.inner.trusted_only(trusted_only);
        self
    }

    #[napi]
    pub fn service(&mut self, service: String) -> &Self {
        self.inner.service(&service);
        self
    }

    #[napi]
    pub fn subject(&mut self, subject: String) -> &Self {
        self.inner.subject(&subject);
        self
    }

    #[napi]
    pub fn account(&mut self, account: String) -> &Self {
        self.inner.account(&account);
        self
    }

    #[napi]
    pub fn access_group(&mut self, access_group: String) -> &Self {
        self.inner.access_group(&access_group);
        self
    }

    #[napi]
    pub fn cloud_sync(&mut self, cloud_sync: CloudSync) -> &Self {
        self.inner.cloud_sync(NativeCloudSync::from(cloud_sync));
        self
    }

    #[napi]
    pub fn access_group_token(&mut self) -> &Self {
        self.inner.access_group_token();
        self
    }

    #[napi]
    pub fn public_key_hash(&mut self, hash: Buffer) -> &Self {
        self.inner.pub_key_hash(&hash);
        self
    }

    #[napi]
    pub fn serial_number(&mut self, serial_number: Buffer) -> &Self {
        self.inner.serial_number(&serial_number);
        self
    }

    #[napi]
    pub fn application_label(&mut self, application_label: Buffer) -> &Self {
        self.inner.application_label(&application_label);
        self
    }

    #[napi]
    pub fn skip_authenticated_items(&mut self, skip: bool) -> &Self {
        self.inner.skip_authenticated_items(skip);
        self
    }

    #[napi]
    pub fn search(&self) -> Result<Vec<ItemSearchResult>> {
        self.inner
            .search()
            .map(|results| results.into_iter().map(search_result).collect())
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&self) -> Result<()> {
        self.inner.delete().map_err(napi_error)
    }
}

fn data_location(keychain: Option<&SecKeychain>, data_protection: bool) -> Location {
    if let Some(keychain) = keychain {
        Location::FileKeychain(keychain.inner.clone())
    } else if data_protection {
        Location::DataProtectionKeychain
    } else {
        Location::DefaultFileKeychain
    }
}

#[napi]
pub struct ItemAddOptions {
    inner: NativeItemAddOptions,
}

#[napi]
impl ItemAddOptions {
    #[napi(factory)]
    pub fn data(item_class: ItemClass, data: Buffer) -> Self {
        Self {
            inner: NativeItemAddOptions::new(ItemAddValue::Data {
                class: item_class.into(),
                data: CFData::from_buffer(&data),
            }),
        }
    }

    #[napi(factory)]
    pub fn key(key: &SecKey) -> Self {
        Self {
            inner: NativeItemAddOptions::new(ItemAddValue::Ref(AddRef::Key(key.inner.clone()))),
        }
    }

    #[napi(factory)]
    pub fn identity(identity: &SecIdentity) -> Self {
        Self {
            inner: NativeItemAddOptions::new(ItemAddValue::Ref(AddRef::Identity(
                identity.inner.clone(),
            ))),
        }
    }

    #[napi(factory)]
    pub fn certificate(certificate: &SecCertificate) -> Self {
        Self {
            inner: NativeItemAddOptions::new(ItemAddValue::Ref(AddRef::Certificate(
                certificate.inner.clone(),
            ))),
        }
    }

    #[napi]
    pub fn set_account_name(&mut self, value: String) -> &Self {
        self.inner.set_account_name(value);
        self
    }

    #[napi]
    pub fn set_access_group(&mut self, value: String) -> &Self {
        self.inner.set_access_group(value);
        self
    }

    #[napi]
    pub fn set_comment(&mut self, value: String) -> &Self {
        self.inner.set_comment(value);
        self
    }

    #[napi]
    pub fn set_description(&mut self, value: String) -> &Self {
        self.inner.set_description(value);
        self
    }

    #[napi]
    pub fn set_label(&mut self, value: String) -> &Self {
        self.inner.set_label(value);
        self
    }

    #[napi]
    pub fn set_service(&mut self, value: String) -> &Self {
        self.inner.set_service(value);
        self
    }

    #[napi]
    pub fn set_default_file_keychain(&mut self) -> &Self {
        self.inner.set_location(Location::DefaultFileKeychain);
        self
    }

    #[napi]
    pub fn set_data_protection_keychain(&mut self) -> &Self {
        self.inner.set_location(Location::DataProtectionKeychain);
        self
    }

    #[napi]
    pub fn set_file_keychain(&mut self, keychain: &SecKeychain) -> &Self {
        self.inner
            .set_location(data_location(Some(keychain), false));
        self
    }

    #[napi]
    pub fn add(&self) -> Result<()> {
        self.inner.add().map_err(napi_error)
    }
}

#[napi]
pub struct ItemUpdateOptions {
    inner: NativeItemUpdateOptions,
}

impl Default for ItemUpdateOptions {
    fn default() -> Self {
        Self {
            inner: NativeItemUpdateOptions::new(),
        }
    }
}

#[napi]
impl ItemUpdateOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn set_data(&mut self, data: Buffer) -> &Self {
        self.inner
            .set_value(ItemUpdateValue::Data(CFData::from_buffer(&data)));
        self
    }

    #[napi]
    pub fn set_key(&mut self, key: &SecKey) -> &Self {
        self.inner
            .set_value(ItemUpdateValue::Ref(AddRef::Key(key.inner.clone())));
        self
    }

    #[napi]
    pub fn set_identity(&mut self, identity: &SecIdentity) -> &Self {
        self.inner.set_value(ItemUpdateValue::Ref(AddRef::Identity(
            identity.inner.clone(),
        )));
        self
    }

    #[napi]
    pub fn set_certificate(&mut self, certificate: &SecCertificate) -> &Self {
        self.inner
            .set_value(ItemUpdateValue::Ref(AddRef::Certificate(
                certificate.inner.clone(),
            )));
        self
    }

    #[napi]
    pub fn set_class(&mut self, item_class: ItemClass) -> &Self {
        self.inner.set_class(item_class.into());
        self
    }

    #[napi]
    pub fn set_account_name(&mut self, value: String) -> &Self {
        self.inner.set_account_name(value);
        self
    }

    #[napi]
    pub fn set_access_group(&mut self, value: String) -> &Self {
        self.inner.set_access_group(value);
        self
    }

    #[napi]
    pub fn set_comment(&mut self, value: String) -> &Self {
        self.inner.set_comment(value);
        self
    }

    #[napi]
    pub fn set_description(&mut self, value: String) -> &Self {
        self.inner.set_description(value);
        self
    }

    #[napi]
    pub fn set_label(&mut self, value: String) -> &Self {
        self.inner.set_label(value);
        self
    }

    #[napi]
    pub fn set_service(&mut self, value: String) -> &Self {
        self.inner.set_service(value);
        self
    }

    #[napi]
    pub fn set_default_file_keychain(&mut self) -> &Self {
        self.inner.set_location(Location::DefaultFileKeychain);
        self
    }

    #[napi]
    pub fn set_data_protection_keychain(&mut self) -> &Self {
        self.inner.set_location(Location::DataProtectionKeychain);
        self
    }

    #[napi]
    pub fn set_file_keychain(&mut self, keychain: &SecKeychain) -> &Self {
        self.inner
            .set_location(data_location(Some(keychain), false));
        self
    }
}

#[napi]
pub fn update_item(search: &ItemSearchOptions, update: &ItemUpdateOptions) -> Result<()> {
    native_update_item(&search.inner, &update.inner).map_err(napi_error)
}

#[napi]
pub struct SecKeychainItem {
    pub(crate) inner: Option<NativeSecKeychainItem>,
}

#[napi]
impl SecKeychainItem {
    #[napi]
    pub fn set_password(&mut self, password: Buffer) -> Result<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("keychain item has been deleted"))?
            .set_password(&password)
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&mut self) {
        if let Some(item) = self.inner.take() {
            item.delete();
        }
    }
}
