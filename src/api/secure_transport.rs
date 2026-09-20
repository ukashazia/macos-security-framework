use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use napi::bindgen_prelude::{Buffer, ClassInstance, Result};
use napi::{Error, Status};
use napi_derive::napi;
use security_framework::cipher_suite::CipherSuite;
use security_framework::os::macos::secure_transport::{MidHandshakeSslStreamExt, SslContextExt};
use security_framework::secure_transport::{
    ClientBuilder as NativeClientBuilder, ClientHandshakeError,
    HandshakeError as NativeHandshakeError,
    MidHandshakeClientBuilder as NativeMidHandshakeClientBuilder,
    MidHandshakeSslStream as NativeMidHandshakeSslStream, ServerBuilder as NativeServerBuilder,
    SessionState as NativeSessionState, SslAuthenticate as NativeSslAuthenticate,
    SslClientCertificateState as NativeSslClientCertificateState,
    SslConnectionType as NativeSslConnectionType, SslContext as NativeSslContext,
    SslProtocol as NativeSslProtocol, SslProtocolSide as NativeSslProtocolSide,
    SslStream as NativeSslStream,
};
use security_framework_sys::cipher_suite::SSLCipherSuite;

use super::error::napi_error;
use super::security::{SecCertificate, SecIdentity, SecTrust};

type TcpSslStream = NativeSslStream<TcpStream>;
type TcpMidHandshakeStream = NativeMidHandshakeSslStream<TcpStream>;
type TcpMidHandshakeClient = NativeMidHandshakeClientBuilder<TcpStream>;

fn consumed(name: &str) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("{name} has already been consumed"),
    )
}

fn native_certificates(
    values: Vec<ClassInstance<'_, SecCertificate>>,
) -> Vec<security_framework::certificate::SecCertificate> {
    values
        .iter()
        .map(|certificate| certificate.inner.clone())
        .collect()
}

fn cipher_suites(values: Vec<u32>) -> Result<Vec<CipherSuite>> {
    values
        .into_iter()
        .map(|value| {
            u16::try_from(value)
                .map(|raw| CipherSuite::from_raw(SSLCipherSuite::from(raw)))
                .map_err(|_| {
                    Error::new(
                        Status::InvalidArg,
                        format!("TLS cipher suite must fit in 16 bits: {value}"),
                    )
                })
        })
        .collect()
}

#[napi(string_enum)]
pub enum SslSide {
    Client,
    Server,
}

impl From<SslSide> for NativeSslProtocolSide {
    fn from(value: SslSide) -> Self {
        match value {
            SslSide::Client => Self::CLIENT,
            SslSide::Server => Self::SERVER,
        }
    }
}

#[napi(string_enum)]
pub enum SslConnectionType {
    Stream,
    Datagram,
}

impl From<SslConnectionType> for NativeSslConnectionType {
    fn from(value: SslConnectionType) -> Self {
        match value {
            SslConnectionType::Stream => Self::STREAM,
            SslConnectionType::Datagram => Self::DATAGRAM,
        }
    }
}

#[napi(string_enum)]
pub enum SslProtocol {
    All,
    Dtls1,
    Ssl2,
    Ssl3,
    Ssl3Only,
    Tls1,
    Tls11,
    Tls12,
    Tls13,
    Tls1Only,
    Unknown,
}

impl From<SslProtocol> for NativeSslProtocol {
    fn from(value: SslProtocol) -> Self {
        match value {
            SslProtocol::All => Self::ALL,
            SslProtocol::Dtls1 => Self::DTLS1,
            SslProtocol::Ssl2 => Self::SSL2,
            SslProtocol::Ssl3 => Self::SSL3,
            SslProtocol::Ssl3Only => Self::SSL3_ONLY,
            SslProtocol::Tls1 => Self::TLS1,
            SslProtocol::Tls11 => Self::TLS11,
            SslProtocol::Tls12 => Self::TLS12,
            SslProtocol::Tls13 => Self::TLS13,
            SslProtocol::Tls1Only => Self::TLS1_ONLY,
            SslProtocol::Unknown => Self::UNKNOWN,
        }
    }
}

impl From<NativeSslProtocol> for SslProtocol {
    fn from(value: NativeSslProtocol) -> Self {
        if value == NativeSslProtocol::ALL {
            Self::All
        } else if value == NativeSslProtocol::DTLS1 {
            Self::Dtls1
        } else if value == NativeSslProtocol::SSL2 {
            Self::Ssl2
        } else if value == NativeSslProtocol::SSL3 {
            Self::Ssl3
        } else if value == NativeSslProtocol::SSL3_ONLY {
            Self::Ssl3Only
        } else if value == NativeSslProtocol::TLS1 {
            Self::Tls1
        } else if value == NativeSslProtocol::TLS11 {
            Self::Tls11
        } else if value == NativeSslProtocol::TLS12 {
            Self::Tls12
        } else if value == NativeSslProtocol::TLS13 {
            Self::Tls13
        } else if value == NativeSslProtocol::TLS1_ONLY {
            Self::Tls1Only
        } else {
            Self::Unknown
        }
    }
}

#[napi(string_enum)]
pub enum SslAuthenticate {
    Always,
    Never,
    Try,
}

impl From<SslAuthenticate> for NativeSslAuthenticate {
    fn from(value: SslAuthenticate) -> Self {
        match value {
            SslAuthenticate::Always => Self::ALWAYS,
            SslAuthenticate::Never => Self::NEVER,
            SslAuthenticate::Try => Self::TRY,
        }
    }
}

#[napi(string_enum)]
pub enum SslSessionState {
    Aborted,
    Closed,
    Connected,
    Handshake,
    Idle,
}

impl From<NativeSessionState> for SslSessionState {
    fn from(value: NativeSessionState) -> Self {
        if value == NativeSessionState::ABORTED {
            Self::Aborted
        } else if value == NativeSessionState::CLOSED {
            Self::Closed
        } else if value == NativeSessionState::CONNECTED {
            Self::Connected
        } else if value == NativeSessionState::HANDSHAKE {
            Self::Handshake
        } else {
            Self::Idle
        }
    }
}

#[napi(string_enum)]
pub enum SslClientCertificateState {
    Rejected,
    Requested,
    Sent,
    None,
}

impl From<NativeSslClientCertificateState> for SslClientCertificateState {
    fn from(value: NativeSslClientCertificateState) -> Self {
        if value == NativeSslClientCertificateState::REJECTED {
            Self::Rejected
        } else if value == NativeSslClientCertificateState::REQUESTED {
            Self::Requested
        } else if value == NativeSslClientCertificateState::SENT {
            Self::Sent
        } else {
            Self::None
        }
    }
}

#[napi(object, object_from_js = false)]
pub struct SocketInfo {
    pub local_address: String,
    pub peer_address: String,
}

fn socket_info(stream: &TcpStream) -> Result<SocketInfo> {
    Ok(SocketInfo {
        local_address: stream.local_addr().map_err(napi_error)?.to_string(),
        peer_address: stream.peer_addr().map_err(napi_error)?.to_string(),
    })
}

#[napi(object, object_from_js = false)]
pub struct HandshakeResult {
    pub stream: Option<SslStream>,
    pub interrupted: Option<MidHandshakeSslStream>,
}

fn handshake_result(
    result: std::result::Result<TcpSslStream, NativeHandshakeError<TcpStream>>,
) -> Result<HandshakeResult> {
    match result {
        Ok(inner) => Ok(HandshakeResult {
            stream: Some(SslStream { inner }),
            interrupted: None,
        }),
        Err(NativeHandshakeError::Interrupted(inner)) => Ok(HandshakeResult {
            stream: None,
            interrupted: Some(MidHandshakeSslStream { inner: Some(inner) }),
        }),
        Err(NativeHandshakeError::Failure(error)) => Err(napi_error(error)),
    }
}

#[napi(object, object_from_js = false)]
pub struct ClientHandshakeResult {
    pub stream: Option<SslStream>,
    pub interrupted: Option<MidHandshakeClientBuilder>,
}

fn client_handshake_result(
    result: std::result::Result<TcpSslStream, ClientHandshakeError<TcpStream>>,
) -> Result<ClientHandshakeResult> {
    match result {
        Ok(inner) => Ok(ClientHandshakeResult {
            stream: Some(SslStream { inner }),
            interrupted: None,
        }),
        Err(ClientHandshakeError::Interrupted(inner)) => Ok(ClientHandshakeResult {
            stream: None,
            interrupted: Some(MidHandshakeClientBuilder { inner: Some(inner) }),
        }),
        Err(ClientHandshakeError::Failure(error)) => Err(napi_error(error)),
    }
}

#[napi]
pub struct SslContext {
    inner: Option<NativeSslContext>,
}

impl SslContext {
    fn inner(&self) -> Result<&NativeSslContext> {
        self.inner.as_ref().ok_or_else(|| consumed("SslContext"))
    }

    fn inner_mut(&mut self) -> Result<&mut NativeSslContext> {
        self.inner.as_mut().ok_or_else(|| consumed("SslContext"))
    }
}

#[napi]
impl SslContext {
    #[napi(constructor)]
    pub fn new(side: SslSide, connection_type: SslConnectionType) -> Result<Self> {
        NativeSslContext::new(side.into(), connection_type.into())
            .map(|inner| Self { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_peer_domain_name(&mut self, name: String) -> Result<&Self> {
        self.inner_mut()?
            .set_peer_domain_name(&name)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn peer_domain_name(&self) -> Result<String> {
        self.inner()?.peer_domain_name().map_err(napi_error)
    }

    #[napi]
    pub fn set_certificate(
        &mut self,
        identity: &SecIdentity,
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> Result<&Self> {
        self.inner_mut()?
            .set_certificate(&identity.inner, &native_certificates(certificates))
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn set_peer_id(&mut self, peer_id: Buffer) -> Result<&Self> {
        self.inner_mut()?
            .set_peer_id(&peer_id)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn peer_id(&self) -> Result<Option<Buffer>> {
        self.inner()?
            .peer_id()
            .map(|value| value.map(|bytes| bytes.to_vec().into()))
            .map_err(napi_error)
    }

    #[napi]
    pub fn supported_ciphers(&self) -> Result<Vec<u32>> {
        self.inner()?
            .supported_ciphers()
            .map(|values| values.iter().map(|value| value.to_raw() as u32).collect())
            .map_err(napi_error)
    }

    #[napi]
    pub fn enabled_ciphers(&self) -> Result<Vec<u32>> {
        self.inner()?
            .enabled_ciphers()
            .map(|values| values.iter().map(|value| value.to_raw() as u32).collect())
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_enabled_ciphers(&mut self, ciphers: Vec<u32>) -> Result<&Self> {
        self.inner_mut()?
            .set_enabled_ciphers(&cipher_suites(ciphers)?)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn negotiated_cipher(&self) -> Result<u32> {
        self.inner()?
            .negotiated_cipher()
            .map(|value| value.to_raw() as u32)
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_client_authenticate(&mut self, auth: SslAuthenticate) -> Result<&Self> {
        self.inner_mut()?
            .set_client_side_authenticate(auth.into())
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn client_certificate_state(&self) -> Result<SslClientCertificateState> {
        self.inner()?
            .client_certificate_state()
            .map(SslClientCertificateState::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn peer_trust(&self) -> Result<Option<SecTrust>> {
        self.inner()?
            .peer_trust2()
            .map(|value| value.map(|inner| SecTrust { inner }))
            .map_err(napi_error)
    }

    #[napi]
    pub fn state(&self) -> Result<SslSessionState> {
        self.inner()?
            .state()
            .map(SslSessionState::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn negotiated_protocol(&self) -> Result<SslProtocol> {
        self.inner()?
            .negotiated_protocol_version()
            .map(SslProtocol::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn protocol_max(&self) -> Result<SslProtocol> {
        self.inner()?
            .protocol_version_max()
            .map(SslProtocol::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_protocol_max(&mut self, protocol: SslProtocol) -> Result<&Self> {
        self.inner_mut()?
            .set_protocol_version_max(protocol.into())
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn protocol_min(&self) -> Result<SslProtocol> {
        self.inner()?
            .protocol_version_min()
            .map(SslProtocol::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_protocol_min(&mut self, protocol: SslProtocol) -> Result<&Self> {
        self.inner_mut()?
            .set_protocol_version_min(protocol.into())
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn alpn_protocols(&self) -> Result<Vec<String>> {
        self.inner()?.alpn_protocols().map_err(napi_error)
    }

    #[napi]
    pub fn set_alpn_protocols(&mut self, protocols: Vec<String>) -> Result<&Self> {
        self.inner_mut()?
            .set_alpn_protocols(&protocols)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn set_session_tickets_enabled(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_session_tickets_enabled(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn buffered_read_size(&self) -> Result<u32> {
        self.inner()?
            .buffered_read_size()
            .map(|value| value as u32)
            .map_err(napi_error)
    }

    #[napi]
    pub fn break_on_server_auth(&self) -> Result<bool> {
        self.inner()?.break_on_server_auth().map_err(napi_error)
    }

    #[napi]
    pub fn set_break_on_server_auth(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_break_on_server_auth(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn break_on_cert_requested(&self) -> Result<bool> {
        self.inner()?.break_on_cert_requested().map_err(napi_error)
    }

    #[napi]
    pub fn set_break_on_cert_requested(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_break_on_cert_requested(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn break_on_client_auth(&self) -> Result<bool> {
        self.inner()?.break_on_client_auth().map_err(napi_error)
    }

    #[napi]
    pub fn set_break_on_client_auth(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_break_on_client_auth(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn false_start(&self) -> Result<bool> {
        self.inner()?.false_start().map_err(napi_error)
    }

    #[napi]
    pub fn set_false_start(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_false_start(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn send_one_byte_record(&self) -> Result<bool> {
        self.inner()?.send_one_byte_record().map_err(napi_error)
    }

    #[napi]
    pub fn set_send_one_byte_record(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_send_one_byte_record(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn diffie_hellman_params(&self) -> Result<Option<Buffer>> {
        self.inner()?
            .diffie_hellman_params()
            .map(|value| value.map(|bytes| bytes.to_vec().into()))
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_diffie_hellman_params(&mut self, params: Buffer) -> Result<&Self> {
        self.inner_mut()?
            .set_diffie_hellman_params(&params)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn certificate_authorities(&self) -> Result<Option<Vec<SecCertificate>>> {
        self.inner()?
            .certificate_authorities()
            .map(|values| {
                values.map(|certificates| {
                    certificates
                        .into_iter()
                        .map(|inner| SecCertificate { inner })
                        .collect()
                })
            })
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_certificate_authorities(
        &mut self,
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> Result<&Self> {
        self.inner_mut()?
            .set_certificate_authorities(&native_certificates(certificates))
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn add_certificate_authorities(
        &mut self,
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> Result<&Self> {
        self.inner_mut()?
            .add_certificate_authorities(&native_certificates(certificates))
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn allow_server_identity_change(&self) -> Result<bool> {
        self.inner()?
            .allow_server_identity_change()
            .map_err(napi_error)
    }

    #[napi]
    pub fn set_allow_server_identity_change(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_allow_server_identity_change(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn fallback(&self) -> Result<bool> {
        self.inner()?.fallback().map_err(napi_error)
    }

    #[napi]
    pub fn set_fallback(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_fallback(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn break_on_client_hello(&self) -> Result<bool> {
        self.inner()?.break_on_client_hello().map_err(napi_error)
    }

    #[napi]
    pub fn set_break_on_client_hello(&mut self, enabled: bool) -> Result<&Self> {
        self.inner_mut()?
            .set_break_on_client_hello(enabled)
            .map_err(napi_error)?;
        Ok(self)
    }

    #[napi]
    pub fn connect(&mut self, host: String, port: u16) -> Result<HandshakeResult> {
        let context = self.inner.take().ok_or_else(|| consumed("SslContext"))?;
        let stream = TcpStream::connect((host, port)).map_err(napi_error)?;
        handshake_result(context.handshake(stream))
    }
}

#[napi]
pub struct SslStream {
    inner: TcpSslStream,
}

#[napi]
impl SslStream {
    #[napi]
    pub fn read(&mut self, length: u32) -> Result<Buffer> {
        let mut data = vec![0; length as usize];
        let count = self.inner.read(&mut data).map_err(napi_error)?;
        data.truncate(count);
        Ok(data.into())
    }

    #[napi]
    pub fn write(&mut self, data: Buffer) -> Result<u32> {
        self.inner
            .write(&data)
            .map(|count| count as u32)
            .map_err(napi_error)
    }

    #[napi]
    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush().map_err(napi_error)
    }

    #[napi]
    pub fn close(&mut self) -> Result<()> {
        self.inner.close().map_err(napi_error)
    }

    #[napi]
    pub fn context(&self) -> SslContext {
        SslContext {
            inner: Some(self.inner.context().clone()),
        }
    }

    #[napi]
    pub fn socket_info(&self) -> Result<SocketInfo> {
        socket_info(self.inner.get_ref())
    }
}

#[napi(object, object_from_js = false)]
pub struct HandshakeInterruption {
    pub error: String,
    pub server_auth_completed: bool,
    pub client_certificate_requested: bool,
    pub would_block: bool,
    pub client_hello_received: bool,
}

#[napi]
pub struct MidHandshakeSslStream {
    inner: Option<TcpMidHandshakeStream>,
}

#[napi]
impl MidHandshakeSslStream {
    #[napi]
    pub fn socket_info(&self) -> Result<SocketInfo> {
        socket_info(
            self.inner
                .as_ref()
                .ok_or_else(|| consumed("MidHandshakeSslStream"))?
                .get_ref(),
        )
    }

    #[napi]
    pub fn context(&self) -> Result<SslContext> {
        Ok(SslContext {
            inner: Some(
                self.inner
                    .as_ref()
                    .ok_or_else(|| consumed("MidHandshakeSslStream"))?
                    .context()
                    .clone(),
            ),
        })
    }

    #[napi]
    pub fn interruption(&self) -> Result<HandshakeInterruption> {
        let stream = self
            .inner
            .as_ref()
            .ok_or_else(|| consumed("MidHandshakeSslStream"))?;
        Ok(HandshakeInterruption {
            error: stream.error().to_string(),
            server_auth_completed: stream.server_auth_completed(),
            client_certificate_requested: stream.client_cert_requested(),
            would_block: stream.would_block(),
            client_hello_received: stream.client_hello_received(),
        })
    }

    #[napi]
    pub fn resume(&mut self) -> Result<HandshakeResult> {
        let stream = self
            .inner
            .take()
            .ok_or_else(|| consumed("MidHandshakeSslStream"))?;
        handshake_result(stream.handshake())
    }
}

#[napi]
pub struct MidHandshakeClientBuilder {
    inner: Option<TcpMidHandshakeClient>,
}

#[napi]
impl MidHandshakeClientBuilder {
    #[napi]
    pub fn socket_info(&self) -> Result<SocketInfo> {
        socket_info(
            self.inner
                .as_ref()
                .ok_or_else(|| consumed("MidHandshakeClientBuilder"))?
                .get_ref(),
        )
    }

    #[napi(getter)]
    pub fn error(&self) -> Result<String> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| consumed("MidHandshakeClientBuilder"))?
            .error()
            .to_string())
    }

    #[napi]
    pub fn resume(&mut self) -> Result<ClientHandshakeResult> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| consumed("MidHandshakeClientBuilder"))?;
        client_handshake_result(builder.handshake())
    }
}

#[napi]
pub struct ClientBuilder {
    inner: NativeClientBuilder,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            inner: NativeClientBuilder::new(),
        }
    }
}

#[napi]
impl ClientBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn anchor_certificates(
        &mut self,
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> &Self {
        self.inner
            .anchor_certificates(&native_certificates(certificates));
        self
    }

    #[napi]
    pub fn add_anchor_certificate(&mut self, certificate: &SecCertificate) -> &Self {
        self.inner.add_anchor_certificate(&certificate.inner);
        self
    }

    #[napi]
    pub fn trust_anchor_certificates_only(&mut self, only: bool) -> &Self {
        self.inner.trust_anchor_certificates_only(only);
        self
    }

    #[napi]
    pub fn danger_accept_invalid_certificates(&mut self, accept: bool) -> &Self {
        self.inner.danger_accept_invalid_certs(accept);
        self
    }

    #[napi]
    pub fn use_sni(&mut self, use_sni: bool) -> &Self {
        self.inner.use_sni(use_sni);
        self
    }

    #[napi]
    pub fn danger_accept_invalid_hostnames(&mut self, accept: bool) -> &Self {
        self.inner.danger_accept_invalid_hostnames(accept);
        self
    }

    #[napi]
    pub fn whitelist_ciphers(&mut self, ciphers: Vec<u32>) -> Result<&Self> {
        self.inner.whitelist_ciphers(&cipher_suites(ciphers)?);
        Ok(self)
    }

    #[napi]
    pub fn blacklist_ciphers(&mut self, ciphers: Vec<u32>) -> Result<&Self> {
        self.inner.blacklist_ciphers(&cipher_suites(ciphers)?);
        Ok(self)
    }

    #[napi]
    pub fn identity(
        &mut self,
        identity: &SecIdentity,
        chain: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> &Self {
        self.inner
            .identity(&identity.inner, &native_certificates(chain));
        self
    }

    #[napi]
    pub fn protocol_min(&mut self, protocol: SslProtocol) -> &Self {
        self.inner.protocol_min(protocol.into());
        self
    }

    #[napi]
    pub fn protocol_max(&mut self, protocol: SslProtocol) -> &Self {
        self.inner.protocol_max(protocol.into());
        self
    }

    #[napi]
    pub fn alpn_protocols(&mut self, protocols: Vec<String>) -> &Self {
        let protocols = protocols.iter().map(String::as_str).collect::<Vec<_>>();
        self.inner.alpn_protocols(&protocols);
        self
    }

    #[napi]
    pub fn enable_session_tickets(&mut self, enable: bool) -> &Self {
        self.inner.enable_session_tickets(enable);
        self
    }

    #[napi]
    pub fn connect(
        &self,
        domain: String,
        host: String,
        port: u16,
    ) -> Result<ClientHandshakeResult> {
        let stream = TcpStream::connect((host, port)).map_err(napi_error)?;
        client_handshake_result(self.inner.handshake(&domain, stream))
    }
}

#[napi]
pub struct ServerBuilder {
    inner: NativeServerBuilder,
}

#[napi]
impl ServerBuilder {
    #[napi(constructor)]
    pub fn new(
        identity: &SecIdentity,
        certificates: Vec<ClassInstance<'_, SecCertificate>>,
    ) -> Self {
        Self {
            inner: NativeServerBuilder::new(&identity.inner, &native_certificates(certificates)),
        }
    }

    #[napi(factory)]
    pub fn from_pkcs12(data: Buffer, passphrase: String) -> Result<Self> {
        NativeServerBuilder::from_pkcs12(&data, &passphrase)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn context(&self) -> Result<SslContext> {
        self.inner
            .new_ssl_context()
            .map(|inner| SslContext { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub fn accept(&self, host: String, port: u16) -> Result<SslStream> {
        let listener = TcpListener::bind((host, port)).map_err(napi_error)?;
        let (stream, _) = listener.accept().map_err(napi_error)?;
        self.inner
            .handshake(stream)
            .map(|inner| SslStream { inner })
            .map_err(napi_error)
    }
}
