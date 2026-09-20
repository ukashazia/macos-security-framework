use napi_derive::napi;
use security_framework::authorization::Flags as NativeAuthorizationFlags;
use security_framework::cms::SignedAttributes as NativeSignedAttributes;
use security_framework::os::macos::code_signing::Flags as NativeCodeSigningFlags;
use security_framework::passwords::AccessControlOptions as NativeAccessControlOptions;
use security_framework::policy::RevocationPolicy as NativeRevocationPolicy;
use security_framework::trust::TrustOptions as NativeTrustOptions;

#[napi(object, object_from_js = false)]
pub struct AccessControlFlagValues {
    pub user_presence: u32,
    pub biometry_any: u32,
    pub biometry_current_set: u32,
    pub device_passcode: u32,
    pub watch: u32,
    pub or: u32,
    pub and: u32,
    pub private_key_usage: u32,
    pub application_password: u32,
}

#[napi]
pub fn access_control_flags() -> AccessControlFlagValues {
    AccessControlFlagValues {
        user_presence: NativeAccessControlOptions::USER_PRESENCE.bits() as u32,
        biometry_any: NativeAccessControlOptions::BIOMETRY_ANY.bits() as u32,
        biometry_current_set: NativeAccessControlOptions::BIOMETRY_CURRENT_SET.bits() as u32,
        device_passcode: NativeAccessControlOptions::DEVICE_PASSCODE.bits() as u32,
        watch: NativeAccessControlOptions::WATCH.bits() as u32,
        or: NativeAccessControlOptions::OR.bits() as u32,
        and: NativeAccessControlOptions::AND.bits() as u32,
        private_key_usage: NativeAccessControlOptions::PRIVATE_KEY_USAGE.bits() as u32,
        application_password: NativeAccessControlOptions::APPLICATION_PASSWORD.bits() as u32,
    }
}

#[napi(object, object_from_js = false)]
pub struct AuthorizationFlagValues {
    pub defaults: u32,
    pub interaction_allowed: u32,
    pub extend_rights: u32,
    pub partial_rights: u32,
    pub destroy_rights: u32,
    pub preauthorize: u32,
}

#[napi]
pub fn authorization_flags() -> AuthorizationFlagValues {
    AuthorizationFlagValues {
        defaults: NativeAuthorizationFlags::DEFAULTS.bits(),
        interaction_allowed: NativeAuthorizationFlags::INTERACTION_ALLOWED.bits(),
        extend_rights: NativeAuthorizationFlags::EXTEND_RIGHTS.bits(),
        partial_rights: NativeAuthorizationFlags::PARTIAL_RIGHTS.bits(),
        destroy_rights: NativeAuthorizationFlags::DESTROY_RIGHTS.bits(),
        preauthorize: NativeAuthorizationFlags::PREAUTHORIZE.bits(),
    }
}

#[napi(object, object_from_js = false)]
pub struct CmsSignedAttributeValues {
    pub smime_capabilities: u32,
    pub smime_encryption_key_preferences: u32,
    pub smime_microsoft_encryption_key_preferences: u32,
    pub signing_time: u32,
    pub apple_code_signing_hash_agility: u32,
    pub apple_code_signing_hash_agility_v2: u32,
    pub apple_expiration_time: u32,
}

#[napi]
pub fn cms_signed_attributes() -> CmsSignedAttributeValues {
    CmsSignedAttributeValues {
        smime_capabilities: NativeSignedAttributes::SMIME_CAPABILITIES.bits(),
        smime_encryption_key_preferences: NativeSignedAttributes::SMIME_ENCRYPTION_KEY_PREFS.bits(),
        smime_microsoft_encryption_key_preferences:
            NativeSignedAttributes::SMIME_MS_ENCRYPTION_KEY_PREFS.bits(),
        signing_time: NativeSignedAttributes::SIGNING_TIME.bits(),
        apple_code_signing_hash_agility: NativeSignedAttributes::APPLE_CODESIGNING_HASH_AGILITY
            .bits(),
        apple_code_signing_hash_agility_v2:
            NativeSignedAttributes::APPLE_CODESIGNING_HASH_AGILITY_V2.bits(),
        apple_expiration_time: NativeSignedAttributes::APPLE_EXPIRATION_TIME.bits(),
    }
}

#[napi(object, object_from_js = false)]
pub struct RevocationPolicyFlagValues {
    pub ocsp_method: u32,
    pub crl_method: u32,
    pub prefer_crl: u32,
    pub require_positive_response: u32,
    pub network_access_disabled: u32,
    pub use_any_method_available: u32,
}

#[napi]
pub fn revocation_policy_flags() -> RevocationPolicyFlagValues {
    RevocationPolicyFlagValues {
        ocsp_method: NativeRevocationPolicy::OCSP_METHOD.bits() as u32,
        crl_method: NativeRevocationPolicy::CRL_METHOD.bits() as u32,
        prefer_crl: NativeRevocationPolicy::PREFER_CRL.bits() as u32,
        require_positive_response: NativeRevocationPolicy::REQUIRE_POSITIVE_RESPONSE.bits() as u32,
        network_access_disabled: NativeRevocationPolicy::NETWORK_ACCESS_DISABLED.bits() as u32,
        use_any_method_available: NativeRevocationPolicy::USE_ANY_METHOD_AVAILABLE.bits() as u32,
    }
}

#[napi(object, object_from_js = false)]
pub struct TrustFlagValues {
    pub allow_expired: u32,
    pub leaf_is_ca: u32,
    pub fetch_issuer_from_network: u32,
    pub allow_expired_root: u32,
    pub require_revocation_per_certificate: u32,
    pub use_trust_settings: u32,
    pub implicit_anchors: u32,
}

#[napi]
pub fn trust_flags() -> TrustFlagValues {
    TrustFlagValues {
        allow_expired: NativeTrustOptions::ALLOW_EXPIRED.bits(),
        leaf_is_ca: NativeTrustOptions::LEAF_IS_CA.bits(),
        fetch_issuer_from_network: NativeTrustOptions::FETCH_ISSUER_FROM_NET.bits(),
        allow_expired_root: NativeTrustOptions::ALLOW_EXPIRED_ROOT.bits(),
        require_revocation_per_certificate: NativeTrustOptions::REQUIRE_REVOCATION_PER_CERT.bits(),
        use_trust_settings: NativeTrustOptions::USE_TRUST_SETTINGS.bits(),
        implicit_anchors: NativeTrustOptions::IMPLICIT_ANCHORS.bits(),
    }
}

#[napi(object, object_from_js = false)]
pub struct CodeSigningFlagValues {
    pub none: u32,
    pub check_all_architectures: u32,
    pub do_not_validate_executable: u32,
    pub do_not_validate_resources: u32,
    pub basic_validate_only: u32,
    pub check_nested_code: u32,
    pub strict_validate: u32,
    pub full_report: u32,
    pub check_gatekeeper_architectures: u32,
    pub restrict_symlinks: u32,
    pub restrict_to_app_like: u32,
    pub restrict_sideband_data: u32,
    pub use_software_signing_certificate: u32,
    pub validate_peh: u32,
    pub single_threaded: u32,
    pub quick_check: u32,
    pub check_trusted_anchors: u32,
    pub report_progress: u32,
    pub no_network_access: u32,
    pub enforce_revocation_checks: u32,
    pub consider_expiration: u32,
}

#[napi]
pub fn code_signing_flags() -> CodeSigningFlagValues {
    CodeSigningFlagValues {
        none: NativeCodeSigningFlags::NONE.bits(),
        check_all_architectures: NativeCodeSigningFlags::CHECK_ALL_ARCHITECTURES.bits(),
        do_not_validate_executable: NativeCodeSigningFlags::DO_NOT_VALIDATE_EXECUTABLE.bits(),
        do_not_validate_resources: NativeCodeSigningFlags::DO_NOT_VALIDATE_RESOURCES.bits(),
        basic_validate_only: NativeCodeSigningFlags::BASIC_VALIDATE_ONLY.bits(),
        check_nested_code: NativeCodeSigningFlags::CHECK_NESTED_CODE.bits(),
        strict_validate: NativeCodeSigningFlags::STRICT_VALIDATE.bits(),
        full_report: NativeCodeSigningFlags::FULL_REPORT.bits(),
        check_gatekeeper_architectures: NativeCodeSigningFlags::CHECK_GATEKEEPER_ARCHITECTURES
            .bits(),
        restrict_symlinks: NativeCodeSigningFlags::RESTRICT_SYMLINKS.bits(),
        restrict_to_app_like: NativeCodeSigningFlags::RESTRICT_TO_APP_LIKE.bits(),
        restrict_sideband_data: NativeCodeSigningFlags::RESTRICT_SIDEBAND_DATA.bits(),
        use_software_signing_certificate: NativeCodeSigningFlags::USE_SOFTWARE_SIGNING_CERT.bits(),
        validate_peh: NativeCodeSigningFlags::VALIDATE_PEH.bits(),
        single_threaded: NativeCodeSigningFlags::SINGLE_THREADED.bits(),
        quick_check: NativeCodeSigningFlags::QUICK_CHECK.bits(),
        check_trusted_anchors: NativeCodeSigningFlags::CHECK_TRUSTED_ANCHORS.bits(),
        report_progress: NativeCodeSigningFlags::REPORT_PROGRESS.bits(),
        no_network_access: NativeCodeSigningFlags::NO_NETWORK_ACCESS.bits(),
        enforce_revocation_checks: NativeCodeSigningFlags::ENFORCE_REVOCATION_CHECKS.bits(),
        consider_expiration: NativeCodeSigningFlags::CONSIDER_EXPIRATION.bits(),
    }
}
