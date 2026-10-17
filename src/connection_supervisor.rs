use crate::behavior::RansomwareMonitor;
use crate::config::Settings;
use crate::history::{EventHistory, EventKind, SecurityEvent};
use crate::quarantine::QuarantineStore;
use crate::realtime::{
    hresult_text, interruptible_wait, notification_path, realtime_worker, reply,
    valid_notification, BlackshardMessage, DriverVerdict, FilterConnectCommunicationPort,
    FilterGetMessage, ProtectionConnection, RealtimeCounters, RealtimeEvent, SharedDetectionEngine,
    WorkItem,
};
use crate::verdict_cache::VerdictCache;
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, HANDLE, S_OK, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const HRESULT_IO_PENDING: i32 = (0x8007_0000u32 | ERROR_IO_PENDING) as i32;
const RECEIVE_WAIT_MILLISECONDS: u32 = 250;

fn cancel_receive(port: HANDLE, overlapped: &OVERLAPPED) {
    unsafe {
        CancelIoEx(port, overlapped);
        let mut transferred = 0u32;
        GetOverlappedResult(port, overlapped, &mut transferred, 1);
    }
}

fn receive_message(
    port: HANDLE,
    event: HANDLE,
    message: &mut BlackshardMessage,
    stop: &AtomicBool,
) -> Result<bool, String> {
    let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
    overlapped.hEvent = event;
    let result = unsafe {
        FilterGetMessage(
            port,
            (message as *mut BlackshardMessage).cast(),
            std::mem::size_of::<BlackshardMessage>() as u32,
            (&mut overlapped as *mut OVERLAPPED).cast(),
        )
    };
    if result == S_OK {
        return Ok(true);
    }
    if result != HRESULT_IO_PENDING {
        return Err(hresult_text(result));
    }

    loop {
        if stop.load(Ordering::Acquire) {
            cancel_receive(port, &overlapped);
            return Ok(false);
        }
        match unsafe { WaitForSingleObject(event, RECEIVE_WAIT_MILLISECONDS) } {
            WAIT_OBJECT_0 => {
                let mut transferred = 0u32;
                if unsafe { GetOverlappedResult(port, &overlapped, &mut transferred, 0) } == 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                return Ok(true);
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                let error = std::io::Error::last_os_error().to_string();
                cancel_receive(port, &overlapped);
                return Err(error);
            }
            status => {
                cancel_receive(port, &overlapped);
                return Err(format!("unexpected receive wait status {status}"));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn connection_loop(
    engine: SharedDetectionEngine,
    quarantine: Arc<QuarantineStore>,
    history: Arc<EventHistory>,
    settings: Arc<RwLock<Settings>>,
    events: mpsc::SyncSender<RealtimeEvent>,
    counters: Arc<Mutex<RealtimeCounters>>,
    stop: Arc<AtomicBool>,
    published_port: Arc<AtomicIsize>,
    verdict_cache: Arc<RwLock<VerdictCache>>,
    definition_generation: Arc<AtomicU64>,
) {
    let port_name: Vec<u16> = "\\BlackshardPort\0".encode_utf16().collect();
    let ransomware_monitor = Arc::new(Mutex::new(RansomwareMonitor::default()));
    let process_trust_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut generation_count = 0u64;
    let mut backoff_secs = 2;

    while !stop.load(Ordering::Acquire) {
        generation_count += 1;
        let _ = events.try_send(RealtimeEvent::Connection(ProtectionConnection::Connecting));
        let mut port_handle: HANDLE = 0;

        log::info!(
            "Attempting connection to driver port (generation {})",
            generation_count
        );
        let connect_result = unsafe {
            FilterConnectCommunicationPort(
                port_name.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut port_handle,
            )
        };

        if connect_result != S_OK {
            let error_text = hresult_text(connect_result);
            log::error!(
                "FilterConnectCommunicationPort failed: connect {} (HRESULT {:X})",
                error_text,
                connect_result
            );
            let _ = events.try_send(RealtimeEvent::Connection(
                ProtectionConnection::Disconnected(format!("connect {error_text}")),
            ));

            interruptible_wait(&stop, Duration::from_secs(backoff_secs));
            backoff_secs = (backoff_secs * 2).min(60);
            continue;
        }

        let receive_event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if receive_event == 0 {
            let error = format!(
                "could not create the minifilter receive event: {}",
                std::io::Error::last_os_error()
            );
            unsafe { CloseHandle(port_handle) };
            let _ = events.try_send(RealtimeEvent::Connection(
                ProtectionConnection::Disconnected(error),
            ));
            interruptible_wait(&stop, Duration::from_secs(backoff_secs));
            backoff_secs = (backoff_secs * 2).min(60);
            continue;
        }

        backoff_secs = 2;
        let uptime_start = Instant::now();

        published_port.store(port_handle, Ordering::Release);
        log::info!("Kernel real-time protection connected via FilterConnectCommunicationPort (generation {})", generation_count);
        let _ = history.append(&SecurityEvent::new(
            EventKind::ProtectionStarted,
            "Kernel real-time protection connected",
        ));
        let _ = events.try_send(RealtimeEvent::Connection(ProtectionConnection::Connected));

        let worker_count = settings
            .read()
            .map(|value| value.worker_count.clamp(1, 8))
            .unwrap_or(2);

        log::info!("Spawning {} realtime workers", worker_count);
        let (sender, receiver) = mpsc::sync_channel::<WorkItem>(worker_count * 16);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut scan_workers = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let engine = Arc::clone(&engine);
            let quarantine = Arc::clone(&quarantine);
            let history = Arc::clone(&history);
            let settings = Arc::clone(&settings);
            let events = events.clone();
            let counters = Arc::clone(&counters);
            let worker_stop = Arc::clone(&stop);
            let ransomware_monitor = Arc::clone(&ransomware_monitor);
            let process_trust_cache = Arc::clone(&process_trust_cache);
            let worker_verdict_cache = Arc::clone(&verdict_cache);
            let worker_definition_generation = Arc::clone(&definition_generation);
            // Named, so a panic in the service log says which thread it took down.
            let spawned = thread::Builder::new()
                .name(format!("realtime-worker-{index}"))
                .spawn(move || {
                    realtime_worker(
                        receiver,
                        engine,
                        quarantine,
                        history,
                        settings,
                        events,
                        counters,
                        worker_stop,
                        ransomware_monitor,
                        process_trust_cache,
                        worker_verdict_cache,
                        worker_definition_generation,
                    )
                });
            scan_workers.push(spawned.expect("failed to spawn a real-time worker thread"));
        }
        let disconnect_reason = loop {
            if stop.load(Ordering::Acquire) {
                break "real-time protection stopped".to_owned();
            }

            #[repr(C, align(16))]
            struct AlignedMessage(BlackshardMessage);

            let mut message = unsafe { std::mem::zeroed::<AlignedMessage>() };
            match receive_message(port_handle, receive_event, &mut message.0, &stop) {
                Ok(true) => {}
                Ok(false) => break "real-time protection stopped".to_owned(),
                Err(error) => {
                    log::error!("FilterGetMessage failed: {error}");
                    break format!("get {error}");
                }
            }

            let message = message.0;
            if !valid_notification(&message.notification) {
                let _ = reply(
                    port_handle,
                    message.header.message_id,
                    DriverVerdict::Allow,
                    0,
                );
                continue;
            }

            let path = notification_path(&message.notification);
            let item = WorkItem {
                port: port_handle,
                message,
            };
            match sender.try_send(item) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(item)) => {
                    let overload_verdict = if item.message.notification.must_enforce != 0 {
                        DriverVerdict::Block
                    } else {
                        DriverVerdict::Allow
                    };
                    let accepted = reply(
                        item.port,
                        item.message.header.message_id,
                        overload_verdict,
                        0,
                    );
                    let _ = accepted;
                    if let Ok(mut value) = counters.lock() {
                        value.bypassed_due_to_load += 1;
                    }
                    let _ = events.try_send(RealtimeEvent::QueueSaturated {
                        process_id: item.message.notification.process_id,
                        path,
                    });
                }
                Err(mpsc::TrySendError::Disconnected(item)) => {
                    let disconnected_verdict = if item.message.notification.must_enforce != 0 {
                        DriverVerdict::Block
                    } else {
                        DriverVerdict::Allow
                    };
                    let _ = reply(
                        item.port,
                        item.message.header.message_id,
                        disconnected_verdict,
                        0,
                    );
                    break "real-time scan workers stopped unexpectedly".to_owned();
                }
            }
        };

        let uptime = uptime_start.elapsed();
        unsafe { CloseHandle(receive_event) };

        drop(sender);
        for worker in scan_workers {
            let _ = worker.join();
        }

        log::warn!(
            "Disconnected. Reason: {}. Uptime: {}s. Generation: {}. Workers: {}.",
            disconnect_reason,
            uptime.as_secs(),
            generation_count,
            worker_count
        );

        if published_port
            .compare_exchange(port_handle, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe { CloseHandle(port_handle) };
        }
        let _ = history.append(&SecurityEvent::new(
            EventKind::ProtectionStopped,
            disconnect_reason.clone(),
        ));
        let _ = events.try_send(RealtimeEvent::Connection(if stop.load(Ordering::Acquire) {
            ProtectionConnection::Stopped
        } else {
            ProtectionConnection::Disconnected(disconnect_reason)
        }));
        if !stop.load(Ordering::Acquire) {
            interruptible_wait(&stop, Duration::from_secs(2));
        }
    }
}
