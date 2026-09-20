use napi::bindgen_prelude::{Buffer, Result};
use napi::{Error, Status};
use napi_derive::napi;
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions as NativePasswordOptions,
    delete_generic_password as native_delete_generic_password,
    delete_generic_password_options as native_delete_generic_password_options,
    delete_internet_password as native_delete_internet_password,
    generic_password as native_generic_password,
    get_generic_password as native_get_generic_password,
    get_internet_password as native_get_internet_password,
    set_generic_password as native_set_generic_password,
    set_generic_password_options as native_set_generic_password_options,
    set_internet_password as native_set_internet_password,
};
use security_framework_sys::keychain::{SecAuthenticationType, SecProtocolType};

use super::error::napi_error;
use super::security::SecAccessControl;

#[napi(string_enum)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    FTP,
    FTPAccount,
    HTTP,
    IRC,
    NNTP,
    POP3,
    SMTP,
    SOCKS,
    IMAP,
    LDAP,
    AppleTalk,
    AFP,
    Telnet,
    SSH,
    FTPS,
    HTTPS,
    HTTPProxy,
    HTTPSProxy,
    FTPProxy,
    CIFS,
    SMB,
    RTSP,
    RTSPProxy,
    DAAP,
    EPPC,
    IPP,
    NNTPS,
    LDAPS,
    TelnetS,
    IMAPS,
    IRCS,
    POP3S,
    CVSpserver,
    SVN,
    Any,
}

impl From<Protocol> for SecProtocolType {
    fn from(value: Protocol) -> Self {
        macro_rules! protocols {
            ($($name:ident),+ $(,)?) => {
                match value {
                    $(Protocol::$name => Self::$name,)+
                }
            };
        }
        protocols!(
            FTP, FTPAccount, HTTP, IRC, NNTP, POP3, SMTP, SOCKS, IMAP, LDAP, AppleTalk, AFP,
            Telnet, SSH, FTPS, HTTPS, HTTPProxy, HTTPSProxy, FTPProxy, CIFS, SMB, RTSP, RTSPProxy,
            DAAP, EPPC, IPP, NNTPS, LDAPS, TelnetS, IMAPS, IRCS, POP3S, CVSpserver, SVN, Any,
        )
    }
}

#[napi(string_enum)]
#[allow(clippy::upper_case_acronyms)]
pub enum AuthenticationType {
    NTLM,
    MSN,
    DPA,
    RPA,
    HTTPBasic,
    HTTPDigest,
    HTMLForm,
    Default,
    Any,
}

impl From<AuthenticationType> for SecAuthenticationType {
    fn from(value: AuthenticationType) -> Self {
        match value {
            AuthenticationType::NTLM => Self::NTLM,
            AuthenticationType::MSN => Self::MSN,
            AuthenticationType::DPA => Self::DPA,
            AuthenticationType::RPA => Self::RPA,
            AuthenticationType::HTTPBasic => Self::HTTPBasic,
            AuthenticationType::HTTPDigest => Self::HTTPDigest,
            AuthenticationType::HTMLForm => Self::HTMLForm,
            AuthenticationType::Default => Self::Default,
            AuthenticationType::Any => Self::Any,
        }
    }
}

#[napi]
pub struct PasswordOptions {
    inner: Option<NativePasswordOptions>,
}

impl PasswordOptions {
    fn inner_mut(&mut self) -> Result<&mut NativePasswordOptions> {
        self.inner.as_mut().ok_or_else(|| {
            Error::new(
                Status::InvalidArg,
                "PasswordOptions has already been consumed".to_owned(),
            )
        })
    }

    fn take(&mut self) -> Result<NativePasswordOptions> {
        self.inner.take().ok_or_else(|| {
            Error::new(
                Status::InvalidArg,
                "PasswordOptions has already been consumed".to_owned(),
            )
        })
    }
}

#[napi]
impl PasswordOptions {
    #[napi(factory)]
    pub fn generic(service: String, account: String) -> Self {
        Self {
            inner: Some(NativePasswordOptions::new_generic_password(
                &service, &account,
            )),
        }
    }

    #[napi(factory)]
    #[allow(clippy::too_many_arguments)]
    pub fn internet(
        server: String,
        security_domain: Option<String>,
        account: String,
        path: String,
        port: Option<u16>,
        protocol: Protocol,
        authentication_type: AuthenticationType,
    ) -> Self {
        Self {
            inner: Some(NativePasswordOptions::new_internet_password(
                &server,
                security_domain.as_deref(),
                &account,
                &path,
                port,
                protocol.into(),
                authentication_type.into(),
            )),
        }
    }

    #[napi]
    pub fn set_access_control_options(&mut self, flags: u32) -> Result<&Self> {
        self.inner_mut()?
            .set_access_control_options(AccessControlOptions::from_bits_retain(flags as usize));
        Ok(self)
    }

    #[napi]
    pub fn set_access_control(&mut self, access_control: &SecAccessControl) -> Result<&Self> {
        self.inner_mut()?
            .set_access_control(access_control.inner.clone());
        Ok(self)
    }

    #[napi]
    pub fn set_access_group(&mut self, group: String) -> Result<&Self> {
        self.inner_mut()?.set_access_group(&group);
        Ok(self)
    }

    #[napi]
    pub fn set_access_synchronized(&mut self, synchronized: Option<bool>) -> Result<&Self> {
        self.inner_mut()?.set_access_synchronized(synchronized);
        Ok(self)
    }

    #[napi]
    pub fn set_comment(&mut self, comment: String) -> Result<&Self> {
        self.inner_mut()?.set_comment(&comment);
        Ok(self)
    }

    #[napi]
    pub fn set_description(&mut self, description: String) -> Result<&Self> {
        self.inner_mut()?.set_description(&description);
        Ok(self)
    }

    #[napi]
    pub fn set_label(&mut self, label: String) -> Result<&Self> {
        self.inner_mut()?.set_label(&label);
        Ok(self)
    }

    #[napi]
    pub fn use_protected_keychain(&mut self) -> Result<&Self> {
        self.inner_mut()?.use_protected_keychain();
        Ok(self)
    }
}

#[napi]
pub fn set_generic_password(service: String, account: String, password: Buffer) -> Result<()> {
    native_set_generic_password(&service, &account, &password).map_err(napi_error)
}

#[napi]
pub fn get_generic_password(service: String, account: String) -> Result<Buffer> {
    native_get_generic_password(&service, &account)
        .map(Buffer::from)
        .map_err(napi_error)
}

#[napi]
pub fn delete_generic_password(service: String, account: String) -> Result<()> {
    native_delete_generic_password(&service, &account).map_err(napi_error)
}

#[napi]
pub fn set_generic_password_options(password: Buffer, options: &mut PasswordOptions) -> Result<()> {
    native_set_generic_password_options(&password, options.take()?).map_err(napi_error)
}

#[napi]
pub fn generic_password(options: &mut PasswordOptions) -> Result<Buffer> {
    native_generic_password(options.take()?)
        .map(Buffer::from)
        .map_err(napi_error)
}

#[napi]
pub fn delete_generic_password_options(options: &mut PasswordOptions) -> Result<()> {
    native_delete_generic_password_options(options.take()?).map_err(napi_error)
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn set_internet_password(
    server: String,
    security_domain: Option<String>,
    account: String,
    path: String,
    port: Option<u16>,
    protocol: Protocol,
    authentication_type: AuthenticationType,
    password: Buffer,
) -> Result<()> {
    native_set_internet_password(
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
pub fn get_internet_password(
    server: String,
    security_domain: Option<String>,
    account: String,
    path: String,
    port: Option<u16>,
    protocol: Protocol,
    authentication_type: AuthenticationType,
) -> Result<Buffer> {
    native_get_internet_password(
        &server,
        security_domain.as_deref(),
        &account,
        &path,
        port,
        protocol.into(),
        authentication_type.into(),
    )
    .map(Buffer::from)
    .map_err(napi_error)
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn delete_internet_password(
    server: String,
    security_domain: Option<String>,
    account: String,
    path: String,
    port: Option<u16>,
    protocol: Protocol,
    authentication_type: AuthenticationType,
) -> Result<()> {
    native_delete_internet_password(
        &server,
        security_domain.as_deref(),
        &account,
        &path,
        port,
        protocol.into(),
        authentication_type.into(),
    )
    .map_err(napi_error)
}
