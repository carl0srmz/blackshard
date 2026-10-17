use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticodeStatus {
    Trusted { publisher: String },

    Unsigned,

    Untrusted(String),

    Error(String),
}

impl AuthenticodeStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted { .. })
    }
}

pub fn verify_current_executable() -> AuthenticodeStatus {
    match std::env::current_exe() {
        Ok(path) => verify_file(&path),
        Err(error) => {
            AuthenticodeStatus::Error(format!("could not locate the running executable: {error}"))
        }
    }
}

pub fn verify_file(path: &Path) -> AuthenticodeStatus {
    platform::verify_file(path)
}

/// How long a trusted result is reused for an unchanged file.
const TRUSTED_CACHE_LIFETIME: Duration = Duration::from_secs(10 * 60);
const TRUSTED_CACHE_CAPACITY: usize = 64;

type TrustedCache = HashMap<(PathBuf, u64, Option<SystemTime>), (Instant, AuthenticodeStatus)>;
static TRUSTED: Mutex<Option<TrustedCache>> = Mutex::new(None);

/// [`verify_file`], reusing a trusted result for a file whose size and modification time have not
/// changed in the last ten minutes.
///
/// Every IPC connection checked both the client and the service, and the UI connects four times a
/// second while a scan runs. Only trusted results are kept, so an unsigned or tampered file is
/// always checked afresh, and replacing a trusted one changes its size or time.
pub fn verify_file_cached(path: &Path) -> AuthenticodeStatus {
    let key = match std::fs::metadata(path) {
        Ok(metadata) => (path.to_path_buf(), metadata.len(), metadata.modified().ok()),
        Err(_) => return verify_file(path),
    };
    {
        let cache = TRUSTED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((checked, status)) = cache.as_ref().and_then(|cache| cache.get(&key)) {
            if checked.elapsed() < TRUSTED_CACHE_LIFETIME {
                return status.clone();
            }
        }
    }
    let status = verify_file(path);
    if status.is_trusted() {
        let mut cache = TRUSTED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cache = cache.get_or_insert_with(HashMap::new);
        if cache.len() >= TRUSTED_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(key, (Instant::now(), status.clone()));
    }
    status
}

#[cfg(windows)]
mod platform {
    use super::{map_winverifytrust_status, AuthenticodeStatus};
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr;

    type Dword = u32;
    type Long = i32;
    type Handle = *mut c_void;
    type Hwnd = *mut c_void;

    const WTD_UI_NONE: Dword = 2;
    const WTD_REVOKE_NONE: Dword = 0;
    const WTD_CHOICE_FILE: Dword = 1;
    const WTD_STATEACTION_IGNORE: Dword = 0;

    const WTD_CACHE_ONLY_URL_RETRIEVAL: Dword = 0x0000_1000;

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const GENERIC_AUTHENTICODE_POLICY: Guid = Guid {
        data1: 0x00aa_c56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    #[repr(C)]
    struct WintrustFileInfo {
        cb_struct: Dword,
        file_path: *const u16,
        file: Handle,
        known_subject: *mut Guid,
    }

    #[repr(C)]
    struct WintrustData {
        cb_struct: Dword,
        policy_callback_data: *mut c_void,
        sip_client_data: *mut c_void,
        ui_choice: Dword,
        revocation_checks: Dword,
        union_choice: Dword,
        file_info: *mut WintrustFileInfo,
        state_action: Dword,
        state_data: Handle,
        url_reference: *mut u16,
        provider_flags: Dword,
        ui_context: Dword,
        signature_settings: *mut c_void,
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(
            window: Hwnd,
            action_id: *const Guid,
            trust_data: *mut WintrustData,
        ) -> Long;
    }

    pub(super) fn verify_file(path: &Path) -> AuthenticodeStatus {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) => {
                return AuthenticodeStatus::Error(format!(
                    "could not open file for signature verification: {error}"
                ))
            }
        };

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide_path.contains(&0) {
            return AuthenticodeStatus::Error(
                "file path contains an embedded NUL character".to_owned(),
            );
        }
        wide_path.push(0);

        let mut file_info = WintrustFileInfo {
            cb_struct: std::mem::size_of::<WintrustFileInfo>() as Dword,
            file_path: wide_path.as_ptr(),
            file: file.as_raw_handle().cast(),
            known_subject: ptr::null_mut(),
        };

        let mut trust_data = WintrustData {
            cb_struct: std::mem::size_of::<WintrustData>() as Dword,
            policy_callback_data: ptr::null_mut(),
            sip_client_data: ptr::null_mut(),
            ui_choice: WTD_UI_NONE,
            revocation_checks: WTD_REVOKE_NONE,
            union_choice: WTD_CHOICE_FILE,
            file_info: &mut file_info,
            state_action: WTD_STATEACTION_IGNORE,
            state_data: ptr::null_mut(),
            url_reference: ptr::null_mut(),
            provider_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ui_context: 0,
            signature_settings: ptr::null_mut(),
        };

        let status = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &GENERIC_AUTHENTICODE_POLICY,
                &mut trust_data,
            )
        };

        map_winverifytrust_status(status)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::AuthenticodeStatus;
    use std::path::Path;

    pub(super) fn verify_file(_path: &Path) -> AuthenticodeStatus {
        AuthenticodeStatus::Error(
            "Authenticode verification is only available on Windows".to_owned(),
        )
    }
}

const ERROR_SUCCESS: i32 = 0;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800b_0001_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800b_0003_u32 as i32;
const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800b_0004_u32 as i32;
const TRUST_E_NOSIGNATURE: i32 = 0x800b_0100_u32 as i32;
const CERT_E_EXPIRED: i32 = 0x800b_0101_u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800b_0109_u32 as i32;
const CERT_E_CHAINING: i32 = 0x800b_010a_u32 as i32;
const CERT_E_REVOKED: i32 = 0x800b_010c_u32 as i32;
const CERT_E_REVOCATION_FAILURE: i32 = 0x800b_010e_u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800b_0111_u32 as i32;
const TRUST_E_CERT_SIGNATURE: i32 = 0x8009_6004_u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x8009_6010_u32 as i32;
const CRYPT_E_REVOCATION_OFFLINE: i32 = 0x8009_2013_u32 as i32;
const CRYPT_E_SECURITY_SETTINGS: i32 = 0x8009_2026_u32 as i32;

fn map_winverifytrust_status(status: i32) -> AuthenticodeStatus {
    match status {
        ERROR_SUCCESS => AuthenticodeStatus::Trusted {
            publisher: "Windows-verified Authenticode publisher".to_owned(),
        },
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
            AuthenticodeStatus::Unsigned
        }
        TRUST_E_BAD_DIGEST => {
            AuthenticodeStatus::Untrusted("the signed file digest does not match".to_owned())
        }
        TRUST_E_CERT_SIGNATURE => AuthenticodeStatus::Untrusted(
            "a certificate in the signing chain has an invalid signature".to_owned(),
        ),
        CERT_E_EXPIRED => AuthenticodeStatus::Untrusted(
            "the signing certificate is expired or not yet valid".to_owned(),
        ),
        CERT_E_UNTRUSTEDROOT => AuthenticodeStatus::Untrusted(
            "the signing chain terminates at an untrusted root".to_owned(),
        ),
        CERT_E_CHAINING => AuthenticodeStatus::Untrusted(
            "Windows could not build the signing certificate chain".to_owned(),
        ),
        CERT_E_REVOKED => {
            AuthenticodeStatus::Untrusted("the signing certificate was revoked".to_owned())
        }
        TRUST_E_EXPLICIT_DISTRUST => AuthenticodeStatus::Untrusted(
            "the signer is explicitly distrusted by Windows policy".to_owned(),
        ),
        TRUST_E_SUBJECT_NOT_TRUSTED => AuthenticodeStatus::Untrusted(
            "the signed file is not trusted by Windows policy".to_owned(),
        ),
        CRYPT_E_SECURITY_SETTINGS => AuthenticodeStatus::Untrusted(
            "local security policy rejected the signing certificate".to_owned(),
        ),
        CERT_E_REVOCATION_FAILURE | CRYPT_E_REVOCATION_OFFLINE => AuthenticodeStatus::Error(
            "certificate revocation status is unavailable in the local cache".to_owned(),
        ),
        other => AuthenticodeStatus::Error(format!(
            "WinVerifyTrust failed with status 0x{:08X}",
            other as u32
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_trusted_without_inventing_a_subject_name() {
        let status = map_winverifytrust_status(ERROR_SUCCESS);
        assert!(status.is_trusted());
        assert_eq!(
            status,
            AuthenticodeStatus::Trusted {
                publisher: "Windows-verified Authenticode publisher".to_owned()
            }
        );
    }

    #[test]
    fn absent_or_unknown_signature_forms_are_unsigned() {
        for status in [
            TRUST_E_NOSIGNATURE,
            TRUST_E_SUBJECT_FORM_UNKNOWN,
            TRUST_E_PROVIDER_UNKNOWN,
        ] {
            assert_eq!(
                map_winverifytrust_status(status),
                AuthenticodeStatus::Unsigned
            );
        }
    }

    #[test]
    fn integrity_and_policy_failures_are_untrusted() {
        for status in [
            TRUST_E_BAD_DIGEST,
            TRUST_E_CERT_SIGNATURE,
            CERT_E_EXPIRED,
            CERT_E_UNTRUSTEDROOT,
            CERT_E_CHAINING,
            CERT_E_REVOKED,
            TRUST_E_EXPLICIT_DISTRUST,
            TRUST_E_SUBJECT_NOT_TRUSTED,
            CRYPT_E_SECURITY_SETTINGS,
        ] {
            assert!(matches!(
                map_winverifytrust_status(status),
                AuthenticodeStatus::Untrusted(_)
            ));
        }
    }

    #[test]
    fn unavailable_revocation_data_is_an_error_not_a_false_distrust() {
        for status in [CERT_E_REVOCATION_FAILURE, CRYPT_E_REVOCATION_OFFLINE] {
            assert!(matches!(
                map_winverifytrust_status(status),
                AuthenticodeStatus::Error(_)
            ));
        }
    }

    #[test]
    fn unknown_provider_status_preserves_the_numeric_code() {
        let status = map_winverifytrust_status(0x8123_4567_u32 as i32);
        assert_eq!(
            status,
            AuthenticodeStatus::Error("WinVerifyTrust failed with status 0x81234567".to_owned())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_verifier_accepts_the_current_pe_file() {
        let status = verify_current_executable();
        assert!(
            !matches!(status, AuthenticodeStatus::Error(_)),
            "well-formed PE verification unexpectedly failed: {status:?}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_explicitly_unsupported() {
        let status = verify_file(Path::new("blackshard"));
        assert!(matches!(status, AuthenticodeStatus::Error(_)));
    }
}
