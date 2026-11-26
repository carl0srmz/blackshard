use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Antimalware::*;
use windows::Win32::System::Com::*;

use blackshard::ipc::{AmsiIpcClient, DetectionVerdictView, SERVICE_AMSI_APP_NAME};

const MY_CLSID: GUID = GUID::from_u128(0x73a5a75d_bf05_4a2c_8c51_64c1ec8b5c92);

/// Live COM objects plus `LockServer` locks. COM unloads the DLL when `DllCanUnloadNow` says so,
/// and unloading it under a live object would leave the host calling into unmapped code.
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);

/// Held by every object this DLL hands out, so it counts toward `OUTSTANDING` until dropped.
struct ModuleReference;

impl ModuleReference {
    fn new() -> Self {
        OUTSTANDING.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for ModuleReference {
    fn drop(&mut self) {
        OUTSTANDING.fetch_sub(1, Ordering::SeqCst);
    }
}

#[implement(IAntimalwareProvider)]
struct BlackshardAmsiProvider {
    _module: ModuleReference,
}

impl IAntimalwareProvider_Impl for BlackshardAmsiProvider {
    fn Scan(&self, stream: Option<&IAmsiStream>) -> Result<AMSI_RESULT> {
        // This runs inside PowerShell, Office and every other AMSI host; a panic unwinding across
        // the COM boundary would abort the host process.
        catch_unwind(AssertUnwindSafe(|| scan(stream))).unwrap_or(Ok(AMSI_RESULT_NOT_DETECTED))
    }

    fn CloseSession(&self, _session: u64) {}

    fn DisplayName(&self) -> Result<PWSTR> {
        let name = "blackshard AMSI provider\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        unsafe {
            let ptr = CoTaskMemAlloc(name.len() * 2) as *mut u16;
            if ptr.is_null() {
                return Err(windows::core::Error::from(E_OUTOFMEMORY));
            }
            std::ptr::copy_nonoverlapping(name.as_ptr(), ptr, name.len());
            Ok(PWSTR::from_raw(ptr))
        }
    }
}

fn scan(stream: Option<&IAmsiStream>) -> Result<AMSI_RESULT> {
    let stream = match stream {
        Some(s) => s,
        None => return Ok(AMSI_RESULT_CLEAN),
    };

    let app_name = read_string_attribute(stream, AMSI_ATTRIBUTE_APP_NAME, "Unknown");
    if app_name == SERVICE_AMSI_APP_NAME {
        // blackshard's service already scanned this content itself; sending it back would scan it
        // twice and apply the rules meant for code about to run to a file at rest.
        return Ok(AMSI_RESULT_NOT_DETECTED);
    }

    // The service takes at most this much. A larger script is read at both ends: reading only the
    // start let a payload hide behind a few megabytes of padding.
    const LIMIT: usize = 4 * 1024 * 1024;
    let mut content = Vec::new();
    match read_size_attribute(stream) {
        Some(size) if size > LIMIT as u64 => {
            read_range(stream, 0, LIMIT / 2, &mut content)?;
            read_range(stream, size - (LIMIT / 2) as u64, LIMIT / 2, &mut content)?;
        }
        _ => read_range(stream, 0, LIMIT, &mut content)?,
    }

    let content_name = read_string_attribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME, "");

    let client = AmsiIpcClient;
    match client.scan(app_name, content_name, content) {
        Ok(DetectionVerdictView::Malicious) => Ok(AMSI_RESULT_DETECTED),
        Ok(DetectionVerdictView::Suspicious) => Ok(AMSI_RESULT_NOT_DETECTED),
        Ok(DetectionVerdictView::Clean) => Ok(AMSI_RESULT_CLEAN),
        Ok(DetectionVerdictView::Error) => Ok(AMSI_RESULT_CLEAN),
        Err(_) => Ok(AMSI_RESULT_CLEAN),
    }
}

/// Appends up to `length` bytes of the stream, starting at `start`, to `content`.
fn read_range(
    stream: &IAmsiStream,
    start: u64,
    length: usize,
    content: &mut Vec<u8>,
) -> Result<()> {
    let mut buffer = vec![0u8; 8192];
    let mut position = start;
    let mut remaining = length;
    while remaining > 0 {
        let mut read = 0u32;
        let read_buffer = &mut buffer[..remaining.min(8192)];
        unsafe {
            stream.Read(position, read_buffer, &mut read)?;
        }
        if read == 0 {
            break;
        }
        let read = (read as usize).min(read_buffer.len());
        content.extend_from_slice(&read_buffer[..read]);
        position += read as u64;
        remaining -= read;
    }
    Ok(())
}

/// The whole content's size, which the host reports as a 64-bit number.
fn read_size_attribute(stream: &IAmsiStream) -> Option<u64> {
    let mut data = [0u8; 8];
    let mut read = 0u32;
    if unsafe { stream.GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, &mut data, &mut read) }.is_err()
        || read != 8
    {
        return None;
    }
    Some(u64::from_le_bytes(data))
}

fn read_string_attribute(
    stream: &IAmsiStream,
    attribute: AMSI_ATTRIBUTE,
    fallback: &str,
) -> String {
    let mut data = vec![0u8; 4096];
    let mut read = 0u32;
    if unsafe { stream.GetAttribute(attribute, &mut data, &mut read) }.is_err() || read < 2 {
        return fallback.to_owned();
    }
    let byte_len = (read as usize).min(data.len()) & !1;
    let utf16 = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u16>(), byte_len / 2) };
    let len = utf16
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(utf16.len());
    String::from_utf16_lossy(&utf16[..len])
}

#[implement(IClassFactory)]
struct ProviderFactory {
    _module: ModuleReference,
}

impl IClassFactory_Impl for ProviderFactory {
    fn CreateInstance(
        &self,
        outer: Option<&IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> Result<()> {
        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let provider: IAntimalwareProvider = BlackshardAmsiProvider {
            _module: ModuleReference::new(),
        }
        .into();
        unsafe { provider.query(iid, object).ok() }
    }

    fn LockServer(&self, lock: BOOL) -> Result<()> {
        if lock.as_bool() {
            OUTSTANDING.fetch_add(1, Ordering::SeqCst);
        } else {
            // An unbalanced unlock from a buggy host must not wrap the count below zero, which
            // would keep the DLL loaded for good.
            let mut count = OUTSTANDING.load(Ordering::SeqCst);
            while count > 0 {
                match OUTSTANDING.compare_exchange_weak(
                    count,
                    count - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(actual) => count = actual,
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    unsafe {
        if *rclsid == MY_CLSID {
            let factory: IClassFactory = ProviderFactory {
                _module: ModuleReference::new(),
            }
            .into();
            factory.query(riid, ppv)
        } else {
            CLASS_E_CLASSNOTAVAILABLE
        }
    }
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if OUTSTANDING.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[no_mangle]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    S_OK
}

#[no_mangle]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    S_OK
}
