use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadinessState {
    Stopped,
    Starting,
    LoadingSettings,
    LoadingDefinitions,
    LoadingFreshClam,
    StartingDetectionWorkers,
    ConnectingDriver,
    ValidatingProtocol,
    Ready,
    Degraded { reason: String },
    Recovering { reason: String },
    Failed { reason: String },
    Stopping,
}

/// How much of the machine blackshard can actually watch.
///
/// The tier is detected rather than configured: the minifilter's presence *is* the tier. See
/// [`detect_protection_tier`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionTier {
    /// The signed minifilter is installed, so every file operation is mediated in the kernel.
    ///
    /// This is the default so that any path which forgets to set the tier errs towards demanding
    /// the driver and reporting a degraded state. Over-reporting protection is the dangerous
    /// direction for an antivirus; a loud false alarm is recoverable, a quiet false assurance is
    /// not.
    #[default]
    Kernel,
    /// No minifilter is installed. AMSI still covers scripts, macros and .NET loads, and on-demand
    /// scanning, quarantine and definition updates are unaffected.
    Userland,
}

impl ProtectionTier {
    pub fn requires_driver(&self) -> bool {
        matches!(self, Self::Kernel)
    }

    /// Short description of what real-time protection actually covers in this tier.
    pub fn coverage_summary(&self) -> &'static str {
        match self {
            Self::Kernel => "files and scripts",
            Self::Userland => "scripts and macros (AMSI)",
        }
    }
}

/// Decides the tier from whether the minifilter binary is installed.
///
/// `install.ps1` writes `blackshard.sys` into the driver store and its uninstall path removes it,
/// so the file's presence tracks whether the driver was ever installed. This cannot wrongly claim
/// kernel protection: an actual connection is what sets `driver_connected`. It only decides
/// whether the *absence* of a driver is expected or a fault.
///
/// A stale `.sys` with no service entry lands in the fault path, which is the same behaviour as
/// before this tiering existed. Querying the service registry key would tighten that if it ever
/// matters.
pub fn detect_protection_tier() -> ProtectionTier {
    let driver = std::path::Path::new(&std::env::var_os("SystemRoot").unwrap_or_else(|| {
        // Only reachable on a machine with no SystemRoot, where nothing else would work either.
        std::ffi::OsString::from(r"C:\Windows")
    }))
    .join("System32")
    .join("drivers")
    .join("blackshard.sys");

    if driver.is_file() {
        ProtectionTier::Kernel
    } else {
        ProtectionTier::Userland
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtectionComponents {
    pub tier: ProtectionTier,
    pub service_operational: bool,
    pub settings_loaded: bool,
    pub native_definitions_loaded: bool,
    pub freshclam_loaded: bool,
    pub freshclam_generation: u64,
    pub rule_generation: u64,
    pub driver_connected: bool,
    pub driver_protocol_validated: bool,
    pub driver_ready_generation: Option<u64>,
    pub quarantine_available: bool,
    pub history_available: bool,
    pub ipc_available: bool,
    pub self_test_passed: bool,
    pub consecutive_health_successes: u32,
    pub consecutive_health_failures: u32,
}

impl ProtectionComponents {
    pub fn mandatory_failures(&self) -> Vec<&'static str> {
        let mut failures = Vec::new();
        for (healthy, name) in [
            (self.service_operational, "service message loop"),
            (self.settings_loaded, "settings"),
            (self.native_definitions_loaded, "native definitions"),
            (
                self.freshclam_loaded && self.freshclam_generation != 0,
                "active FreshClam database",
            ),
            (self.rule_generation != 0, "rule generation"),
            (self.quarantine_available, "quarantine store"),
            (self.history_available, "event history"),
            (self.ipc_available, "local control server"),
            (self.self_test_passed, "end-to-end self-test"),
        ] {
            if !healthy {
                failures.push(name);
            }
        }

        // The minifilter is only load-bearing when it is actually installed. Without it the agent
        // still protects through AMSI, on-demand scanning and quarantine, so its absence is a
        // supported configuration rather than a failure. A driver that *is* installed but will not
        // connect remains a fault.
        if self.tier.requires_driver() {
            if !self.driver_connected {
                failures.push("minifilter connection");
            }
            if !self.driver_protocol_validated {
                failures.push("driver protocol");
            }
        }

        failures
    }
}

pub fn derive_readiness(components: &ProtectionComponents) -> ReadinessState {
    let failures = components.mandatory_failures();
    if !failures.is_empty() {
        return ReadinessState::Degraded {
            reason: format!("Unavailable: {}", failures.join(", ")),
        };
    }
    if components.tier.requires_driver() && components.driver_ready_generation.is_none() {
        return ReadinessState::Recovering {
            reason: "Arming the validated driver generation".to_owned(),
        };
    }
    if components.consecutive_health_successes < 3 {
        return ReadinessState::Recovering {
            reason: format!(
                "Validating stable protection ({}/3)",
                components.consecutive_health_successes
            ),
        };
    }
    ReadinessState::Ready
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostics {
    pub current_state: ReadinessState,
    pub state_entered_at: DateTime<Utc>,
    pub history: Vec<(ReadinessState, DateTime<Utc>)>,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
}

pub struct ReadinessMonitorInner {
    pub current_state: ReadinessState,
    pub state_entered_at: DateTime<Utc>,
    pub history: Vec<(ReadinessState, DateTime<Utc>)>,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
}

impl ReadinessMonitorInner {
    fn transition(&mut self, next_state: ReadinessState) {
        if self.current_state != next_state {
            let now = Utc::now();
            self.history
                .push((self.current_state.clone(), self.state_entered_at));
            log::info!(
                "Readiness transitioning from {:?} to {:?}",
                self.current_state,
                next_state
            );
            self.current_state = next_state;
            self.state_entered_at = now;
        }
    }
}

#[derive(Clone)]
pub struct ReadinessMonitor {
    inner: Arc<Mutex<ReadinessMonitorInner>>,
}

impl ReadinessMonitor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReadinessMonitorInner {
                current_state: ReadinessState::Stopped,
                state_entered_at: Utc::now(),
                history: Vec::new(),
                consecutive_successes: 0,
                consecutive_failures: 0,
            })),
        }
    }

    pub fn update_state(&self, new_state: ReadinessState) {
        assert!(
            !matches!(new_state, ReadinessState::Ready),
            "Ready must be derived from ProtectionComponents"
        );
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.transition(new_state);
    }

    pub fn report_components(&self, components: &ProtectionComponents) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.consecutive_successes = components.consecutive_health_successes;
        inner.consecutive_failures = components.consecutive_health_failures;
        let derived = derive_readiness(components);
        let explicit_driver_failure =
            !components.driver_connected || !components.driver_protocol_validated;
        if matches!(inner.current_state, ReadinessState::Ready)
            && matches!(derived, ReadinessState::Degraded { .. })
            && !explicit_driver_failure
            && components.consecutive_health_failures < 2
        {
            return;
        }
        if matches!(
            inner.current_state,
            ReadinessState::Stopping | ReadinessState::Stopped | ReadinessState::Failed { .. }
        ) {
            return;
        }
        inner.transition(derived);
    }

    pub fn diagnostics(&self) -> Diagnostics {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Diagnostics {
            current_state: inner.current_state.clone(),
            state_entered_at: inner.state_entered_at,
            history: inner.history.clone(),
            consecutive_successes: inner.consecutive_successes,
            consecutive_failures: inner.consecutive_failures,
        }
    }
}

impl Default for ReadinessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_components() -> ProtectionComponents {
        ProtectionComponents {
            tier: ProtectionTier::Kernel,
            service_operational: true,
            settings_loaded: true,
            native_definitions_loaded: true,
            freshclam_loaded: true,
            freshclam_generation: 7,
            rule_generation: 4,
            driver_connected: true,
            driver_protocol_validated: true,
            driver_ready_generation: Some(9),
            quarantine_available: true,
            history_available: true,
            ipc_available: true,
            self_test_passed: true,
            consecutive_health_successes: 3,
            consecutive_health_failures: 0,
        }
    }

    #[test]
    fn ready_is_derived_only_after_every_mandatory_component_and_hysteresis() {
        let mut components = healthy_components();
        assert_eq!(derive_readiness(&components), ReadinessState::Ready);

        components.consecutive_health_successes = 2;
        assert!(matches!(
            derive_readiness(&components),
            ReadinessState::Recovering { .. }
        ));

        components.consecutive_health_successes = 3;
        components.freshclam_loaded = false;
        assert!(matches!(
            derive_readiness(&components),
            ReadinessState::Degraded { .. }
        ));
    }

    #[test]
    fn missing_driver_or_self_test_never_reports_ready() {
        for mutate in [
            |components: &mut ProtectionComponents| components.driver_connected = false,
            |components: &mut ProtectionComponents| components.self_test_passed = false,
            |components: &mut ProtectionComponents| components.quarantine_available = false,
        ] {
            let mut components = healthy_components();
            mutate(&mut components);
            assert!(!matches!(
                derive_readiness(&components),
                ReadinessState::Ready
            ));
        }
    }

    #[test]
    fn the_userland_tier_reaches_ready_without_any_driver() {
        let mut components = healthy_components();
        components.tier = ProtectionTier::Userland;
        components.driver_connected = false;
        components.driver_protocol_validated = false;
        components.driver_ready_generation = None;

        assert_eq!(components.mandatory_failures(), Vec::<&str>::new());
        assert_eq!(derive_readiness(&components), ReadinessState::Ready);
    }

    #[test]
    fn an_installed_driver_that_will_not_connect_is_still_a_fault() {
        let mut components = healthy_components();
        components.driver_connected = false;

        // Same missing driver as the userland case above, but this machine has one installed, so
        // its absence is a failure rather than a supported configuration.
        assert!(components
            .mandatory_failures()
            .contains(&"minifilter connection"));
        assert!(matches!(
            derive_readiness(&components),
            ReadinessState::Degraded { .. }
        ));
    }

    #[test]
    fn the_userland_tier_still_requires_everything_that_does_not_need_a_driver() {
        for mutate in [
            |components: &mut ProtectionComponents| components.self_test_passed = false,
            |components: &mut ProtectionComponents| components.native_definitions_loaded = false,
            |components: &mut ProtectionComponents| components.quarantine_available = false,
        ] {
            let mut components = healthy_components();
            components.tier = ProtectionTier::Userland;
            mutate(&mut components);
            assert!(!matches!(
                derive_readiness(&components),
                ReadinessState::Ready
            ));
        }
    }

    #[test]
    fn the_tier_defaults_to_demanding_the_driver() {
        // Over-reporting protection is the dangerous direction, so a forgotten tier must fail
        // loudly rather than quietly claim coverage it does not have.
        assert_eq!(ProtectionTier::default(), ProtectionTier::Kernel);
        assert!(ProtectionTier::default().requires_driver());
        assert!(!ProtectionTier::Userland.requires_driver());
    }
}
