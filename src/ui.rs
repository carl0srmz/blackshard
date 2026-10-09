use crate::config::Settings;
use crate::elevation::{self, QuarantineAdminAction};
use crate::history::{EventKind, SecurityEvent};
use crate::ipc::{
    DetectionVerdictView, IpcClient, QuarantineRecordView, RpcErrorCode, ScanFindingView,
    ScanPhaseView, ScanRequestKind, ServiceScanJob,
};
use crate::quarantine::IsolationState;
use chrono::{DateTime, Local, Utc};
use eframe::egui::{self, Align, Color32, FontFamily, FontId, Layout, RichText, Stroke};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

// blackshard.dev's palette: black, white and one yellow, set in JetBrains Mono.
const BG: Color32 = Color32::BLACK;
/// The site's nav bar, one step up from black; also input wells and hover.
const BAR: Color32 = Color32::from_rgb(17, 17, 17);
const RULE: Color32 = Color32::from_rgb(46, 46, 46);
const TEXT: Color32 = Color32::WHITE;
const MUTED: Color32 = Color32::from_rgb(140, 140, 140);
/// The site's yellow: where to look and what to press.
const SIGNAL: Color32 = Color32::from_rgb(255, 255, 0);
/// Kept for threats and failures only, so red always means something is wrong.
const ALARM: Color32 = Color32::from_rgb(255, 64, 64);
// Status roles. A healthy machine reads quiet and monochrome; yellow speaks up; red alarms.
const OK: Color32 = TEXT;
const ATTENTION: Color32 = SIGNAL;
const PENDING: Color32 = MUTED;

const REGULAR_FONT: &str = "jetbrains-mono";
const BOLD_FONT: &str = "jetbrains-mono-bold";
/// The site tracks its type in by 0.089em; slightly less keeps small sizes legible on screen.
const TRACKING: f32 = -0.06;

const ACTIVITY_LIMIT: usize = 500;
const REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const SETTINGS_SAVE_DEBOUNCE: Duration = Duration::from_millis(650);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionStatus {
    Starting,
    Active,
    Paused,
    Degraded(String),
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverStatus {
    Checking,
    Connected,
    Disconnected(String),
    /// The minifilter was never installed. Real-time coverage falls back to AMSI, which is a
    /// supported configuration rather than a fault, so this is not reported in red.
    NotRequired,
    /// The minifilter is installed but unusable, which *is* a fault.
    NotInstalled,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildTrustStatus {
    Checking,
    AuthenticodeVerified { publisher: String },
    UnsignedDevelopmentBuild,
    VerificationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificationStatus {
    NotEvaluated,
    EvaluationInProgress,
    IndependentlyCertified { authority: String },
}

#[derive(Debug, Clone)]
pub enum DefinitionStatus {
    BuiltInOnly {
        version: String,
    },
    Updating {
        current_version: Option<String>,
    },
    Current {
        version: String,
        expires_at: DateTime<Utc>,
    },
    Stale {
        version: String,
        expired_at: DateTime<Utc>,
    },
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionTestStatus {
    Idle,
    Requested,
    Running,
    Passed(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct UiRuntimeState {
    pub protection: ProtectionStatus,
    pub driver: DriverStatus,
    pub tier: crate::readiness::ProtectionTier,
    pub build_trust: BuildTrustStatus,
    pub certification: CertificationStatus,
    pub definitions: DefinitionStatus,
    pub protection_test: ProtectionTestStatus,
    pub realtime_scanned_files: u64,
    pub realtime_blocked_files: u64,
    pub realtime_bypassed_requests: u64,
    pub last_realtime_path: Option<PathBuf>,
    pub desired_real_time_protection: bool,
    pub update_check_requested: bool,
    pub engine_version: String,
    pub freshclam_version: Option<String>,
    pub freshclam_age_hours: Option<u64>,
    pub attention: Option<String>,
    pub readiness: Option<crate::readiness::ReadinessState>,
}

impl Default for UiRuntimeState {
    fn default() -> Self {
        Self {
            protection: ProtectionStatus::Starting,
            driver: DriverStatus::Checking,
            tier: crate::readiness::ProtectionTier::default(),
            build_trust: BuildTrustStatus::Checking,
            certification: CertificationStatus::NotEvaluated,
            definitions: DefinitionStatus::BuiltInOnly {
                version: "embedded".to_owned(),
            },
            protection_test: ProtectionTestStatus::Idle,
            realtime_scanned_files: 0,
            realtime_blocked_files: 0,
            realtime_bypassed_requests: 0,
            last_realtime_path: None,
            desired_real_time_protection: true,
            update_check_requested: false,
            engine_version: crate::product_version(),
            freshclam_version: None,
            freshclam_age_hours: None,
            attention: None,
            readiness: None,
        }
    }
}

pub type SharedUiState = Arc<Mutex<UiRuntimeState>>;

pub fn new_shared_ui_state() -> SharedUiState {
    Arc::new(Mutex::new(UiRuntimeState::default()))
}

pub fn take_protection_test_request(state: &SharedUiState) -> bool {
    let Ok(mut state) = state.lock() else {
        return false;
    };
    if state.protection_test == ProtectionTestStatus::Requested {
        state.protection_test = ProtectionTestStatus::Running;
        true
    } else {
        false
    }
}

pub fn complete_protection_test(state: &SharedUiState, result: Result<String, String>) {
    if let Ok(mut state) = state.lock() {
        state.protection_test = match result {
            Ok(detail) => ProtectionTestStatus::Passed(detail),
            Err(error) => ProtectionTestStatus::Failed(error),
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Scan,
    Quarantine,
    Activity,
    Settings,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "status",
            Self::Scan => "scan",
            Self::Quarantine => "quarantine",
            Self::Activity => "activity",
            Self::Settings => "settings",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum NoticeLevel {
    Information,
    Success,
    Warning,
    Error,
}

struct Notice {
    level: NoticeLevel,
    message: String,
    created: Instant,
}

#[derive(Clone)]
enum Confirmation {
    Restore(QuarantineRecordView),
    Delete(QuarantineRecordView),
    ClearActivity,
}

#[derive(Debug, Clone, Copy)]
enum QuarantineOperation {
    Restore,
    Delete,
}

struct QuarantineOutcome {
    id: Uuid,
    operation: QuarantineOperation,
    result: Result<String, String>,
}

pub struct BlackshardApp {
    runtime: SharedUiState,
    client: IpcClient,
    settings: Settings,
    settings_dirty: bool,
    settings_save_at: Option<Instant>,
    page: Page,
    scan_job: Option<ServiceScanJob>,
    last_handled_scan: Option<Uuid>,
    custom_scan_path: String,
    exclusion_input: String,
    quarantine_records: Vec<QuarantineRecordView>,
    activity: Vec<SecurityEvent>,
    persistent_error: Option<String>,
    /// False until the service has supplied the machine's real settings. Until then the page
    /// shows defaults, and saving is refused so they cannot overwrite what is configured.
    settings_loaded: bool,
    notice: Option<Notice>,
    confirmation: Option<Confirmation>,
    busy_quarantine: HashSet<Uuid>,
    operation_sender: mpsc::Sender<QuarantineOutcome>,
    operation_receiver: mpsc::Receiver<QuarantineOutcome>,
    refresh_at: Instant,
}

impl BlackshardApp {
    pub fn new(runtime: SharedUiState, client: IpcClient) -> Self {
        let service_down = runtime
            .lock()
            .is_ok_and(|state| matches!(state.protection, ProtectionStatus::Unavailable(_)));
        let loaded = if service_down {
            None
        } else {
            Some(client.get_settings())
        };
        let (settings, load_warning) = match loaded {
            Some(Ok(settings)) => (settings, None),
            // The dashboard already explains a stopped service; this only has to say what it
            // means for the settings page.
            None => (
                Settings::default(),
                Some(
                    "settings will load once the protection service is running. until then \
                     you're seeing defaults, and changes can't be saved."
                        .to_owned(),
                ),
            ),
            Some(Err(error)) if error.is_service_unavailable() => (
                Settings::default(),
                Some(
                    "settings will load once the protection service is running. until then \
                     you're seeing defaults, and changes can't be saved."
                        .to_owned(),
                ),
            ),
            Some(Err(error)) => (
                Settings::default(),
                Some(format!(
                    "the protection service could not provide settings, so you're seeing defaults and \
                     changes cannot be saved: {error}"
                )),
            ),
        };
        let settings_loaded = load_warning.is_none();
        if let Ok(mut shared) = runtime.lock() {
            shared.desired_real_time_protection = settings.real_time_protection;
        }

        let (operation_sender, operation_receiver) = mpsc::channel();
        let mut app = Self {
            runtime,
            client,
            settings,
            settings_dirty: false,
            settings_save_at: None,
            page: Page::Dashboard,
            scan_job: None,
            last_handled_scan: None,
            custom_scan_path: String::new(),
            exclusion_input: String::new(),
            quarantine_records: Vec::new(),
            activity: Vec::new(),
            persistent_error: None,
            settings_loaded,
            notice: load_warning.map(|message| Notice {
                level: NoticeLevel::Warning,
                message,
                created: Instant::now(),
            }),
            confirmation: None,
            busy_quarantine: HashSet::new(),
            operation_sender,
            operation_receiver,
            refresh_at: Instant::now(),
        };
        app.refresh_persistent_views();
        app
    }

    pub fn with_machine_defaults(runtime: SharedUiState) -> Self {
        Self::new(runtime, IpcClient)
    }

    fn runtime_snapshot(&self) -> UiRuntimeState {
        match self.runtime.lock() {
            Ok(state) => state.clone(),
            Err(_) => UiRuntimeState {
                protection: ProtectionStatus::Unavailable(
                    "the runtime health channel is unavailable".to_owned(),
                ),
                driver: DriverStatus::Error("the runtime status lock was poisoned".to_owned()),
                attention: Some(
                    "blackshard cannot verify protection state; restart the application."
                        .to_owned(),
                ),
                ..UiRuntimeState::default()
            },
        }
    }

    fn refresh_persistent_views(&mut self) {
        // Every call to a service that is not there waits out the pipe timeout, and this runs on
        // the UI thread, so while health says the service is down the window would freeze for
        // seconds at a time. Check back soon instead; health is re-read every second.
        if matches!(
            self.runtime_snapshot().protection,
            ProtectionStatus::Unavailable(_)
        ) {
            self.persistent_error = None;
            self.refresh_at = Instant::now() + Duration::from_secs(2);
            return;
        }
        if !self.settings_loaded {
            if let Ok(settings) = self.client.get_settings() {
                if let Ok(mut shared) = self.runtime.lock() {
                    shared.desired_real_time_protection = settings.real_time_protection;
                }
                self.settings = settings;
                self.settings_loaded = true;
                self.settings_dirty = false;
                self.settings_save_at = None;
                self.notice = Some(Notice {
                    level: NoticeLevel::Success,
                    message: "connected to the protection service. settings loaded.".to_owned(),
                    created: Instant::now(),
                });
            }
        }
        let mut errors = Vec::new();
        match self.client.list_quarantine() {
            Ok(records) => self.quarantine_records = records,
            Err(error) => errors.push(format!("Could not read quarantine: {error}")),
        }
        match self.client.recent_activity(ACTIVITY_LIMIT) {
            Ok(events) => self.activity = events,
            Err(error) => errors.push(format!("Could not read activity history: {error}")),
        }
        self.persistent_error = if errors.is_empty() {
            None
        } else {
            Some(errors.join(" "))
        };
        self.refresh_at = Instant::now() + REFRESH_INTERVAL;
    }

    fn poll_background_work(&mut self) {
        while let Ok(outcome) = self.operation_receiver.try_recv() {
            self.busy_quarantine.remove(&outcome.id);
            let action = match outcome.operation {
                QuarantineOperation::Restore => "Restore",
                QuarantineOperation::Delete => "Delete",
            };
            self.notice = Some(match outcome.result {
                Ok(detail) => Notice {
                    level: NoticeLevel::Success,
                    message: format!("{action} done. {detail}"),
                    created: Instant::now(),
                },
                Err(error) => Notice {
                    level: NoticeLevel::Error,
                    message: format!("{action} failed: {error}"),
                    created: Instant::now(),
                },
            });
            self.refresh_persistent_views();
        }

        let completed_scan = self.scan_job.as_ref().and_then(|job| {
            let snapshot = job.snapshot();
            (snapshot.is_finished() && self.last_handled_scan != Some(snapshot.id))
                .then_some(snapshot.id)
        });
        if let Some(id) = completed_scan {
            if let Some(job) = self.scan_job.as_mut() {
                job.join_if_finished();
            }
            self.last_handled_scan = Some(id);
            self.refresh_persistent_views();
        }

        if Instant::now() >= self.refresh_at {
            self.refresh_persistent_views();
        }

        if self
            .settings_save_at
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.save_settings();
        }

        if self
            .notice
            .as_ref()
            .is_some_and(|notice| notice.created.elapsed() > Duration::from_secs(10))
        {
            self.notice = None;
        }
    }

    fn start_scan(&mut self, kind: ScanRequestKind) {
        let already_running = self
            .scan_job
            .as_ref()
            .is_some_and(|job| !job.snapshot().is_finished());
        if already_running {
            self.notice = Some(Notice {
                level: NoticeLevel::Warning,
                message: "a scan is already running. stop it before starting another.".to_owned(),
                created: Instant::now(),
            });
            return;
        }

        self.last_handled_scan = None;
        self.scan_job = match ServiceScanJob::start(self.client.clone(), kind) {
            Ok(job) => Some(job),
            Err(error) => {
                self.notice = Some(Notice {
                    level: NoticeLevel::Error,
                    message: format!("the scan could not start: {error}"),
                    created: Instant::now(),
                });
                return;
            }
        };
        self.page = Page::Scan;
        self.notice = Some(Notice {
            level: NoticeLevel::Information,
            message: "scan started. it keeps going while you look at other pages.".to_owned(),
            created: Instant::now(),
        });
    }

    fn start_custom_scan(&mut self) {
        let value = self.custom_scan_path.trim().trim_matches('"');
        if value.is_empty() {
            self.notice = Some(Notice {
                level: NoticeLevel::Warning,
                message: "type the path of a file or folder to scan.".to_owned(),
                created: Instant::now(),
            });
            return;
        }
        let path = PathBuf::from(value);
        if !path.exists() {
            self.notice = Some(Notice {
                level: NoticeLevel::Error,
                message: format!("nothing exists at {}", path.display()),
                created: Instant::now(),
            });
            return;
        }
        self.start_scan(ScanRequestKind::Custom {
            roots: vec![path.to_string_lossy().into_owned()],
        });
    }

    fn save_settings(&mut self) {
        self.settings_save_at = None;
        if !self.settings_loaded {
            self.notice = Some(Notice {
                level: NoticeLevel::Warning,
                message: "Settings cannot be saved until they have loaded from the protection \
                          service."
                    .to_owned(),
                created: Instant::now(),
            });
            return;
        }
        match self.client.save_settings(self.settings.clone()) {
            Ok(_) => {
                self.settings_dirty = false;
                if let Ok(mut runtime) = self.runtime.lock() {
                    runtime.desired_real_time_protection = self.settings.real_time_protection;
                }
                self.notice = Some(Notice {
                    level: NoticeLevel::Success,
                    message: "settings saved.".to_owned(),
                    created: Instant::now(),
                });
            }
            Err(error) if error.code == RpcErrorCode::AccessDenied => {
                self.settings_dirty = false;
                self.notice = Some(match elevation::request_save_settings(&self.settings) {
                    Ok(()) => Notice {
                        level: NoticeLevel::Information,
                        message:
                            "approve the windows administrator prompt to apply these settings."
                                .to_owned(),
                        created: Instant::now(),
                    },
                    Err(error) => Notice {
                        level: NoticeLevel::Error,
                        message: format!("administrator approval could not be requested: {error}"),
                        created: Instant::now(),
                    },
                });
            }
            Err(error) => {
                self.notice = Some(Notice {
                    level: NoticeLevel::Error,
                    message: format!("settings could not be saved: {error}"),
                    created: Instant::now(),
                });
            }
        }
    }

    fn queue_settings_save(&mut self) {
        self.settings_dirty = true;
        self.settings_save_at = Some(Instant::now() + SETTINGS_SAVE_DEBOUNCE);
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.desired_real_time_protection = self.settings.real_time_protection;
        }
    }

    fn begin_quarantine_operation(&mut self, operation: QuarantineOperation, id: Uuid) {
        if !self.busy_quarantine.insert(id) {
            return;
        }
        let client = self.client.clone();
        let sender = self.operation_sender.clone();
        thread::spawn(move || {
            let result = match operation {
                QuarantineOperation::Restore => client.restore_quarantine(id),
                QuarantineOperation::Delete => client.delete_quarantine(id),
            }
            .or_else(|error| {
                if error.code != RpcErrorCode::AccessDenied {
                    return Err(error.to_string());
                }
                let action = match operation {
                    QuarantineOperation::Restore => QuarantineAdminAction::Restore,
                    QuarantineOperation::Delete => QuarantineAdminAction::Delete,
                };
                elevation::request_quarantine_action(action, id).map(|()| {
                    "Approve the Windows administrator prompt; the list will refresh automatically."
                        .to_owned()
                })
            })
            .map_err(|error| error.to_string());
            let _ = sender.send(QuarantineOutcome {
                id,
                operation,
                result,
            });
        });
    }

    /// Installs blackshard's look. Called once, before the first frame: the root `Ui` of a frame
    /// is styled before the app runs, so a style set during a frame never reaches it.
    pub fn apply_theme(ctx: &egui::Context) {
        install_fonts(ctx);
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(TEXT);
        visuals.panel_fill = BG;
        visuals.window_fill = BG;
        visuals.window_stroke = Stroke::new(1.0_f32, TEXT);
        visuals.window_corner_radius = egui::CornerRadius::ZERO;
        visuals.window_shadow = egui::Shadow::NONE;
        visuals.popup_shadow = egui::Shadow::NONE;
        visuals.menu_corner_radius = egui::CornerRadius::ZERO;
        visuals.extreme_bg_color = BAR;
        visuals.faint_bg_color = BAR;
        visuals.code_bg_color = BAR;
        visuals.selection.bg_fill = SIGNAL.gamma_multiply(0.35);
        visuals.selection.stroke = Stroke::new(1.0_f32, SIGNAL);
        visuals.hyperlink_color = SIGNAL;
        visuals.warn_fg_color = SIGNAL;
        visuals.error_fg_color = ALARM;
        visuals.text_cursor.stroke = Stroke::new(2.0_f32, SIGNAL);
        let widgets = &mut visuals.widgets;
        for (state, fill, stroke, foreground) in [
            (&mut widgets.noninteractive, BG, RULE, TEXT),
            (&mut widgets.inactive, BG, MUTED, TEXT),
            (&mut widgets.hovered, BAR, TEXT, TEXT),
            (&mut widgets.active, BAR, SIGNAL, SIGNAL),
            (&mut widgets.open, BAR, SIGNAL, TEXT),
        ] {
            state.bg_fill = fill;
            state.weak_bg_fill = fill;
            state.bg_stroke = Stroke::new(1.0_f32, stroke);
            state.fg_stroke = Stroke::new(1.0_f32, foreground);
            state.corner_radius = egui::CornerRadius::ZERO;
            state.expansion = 0.0;
        }

        // Both the dark and light style slots, so the theme holds whichever one egui selects.
        ctx.all_styles_mut(|style| {
            use egui::TextStyle;
            style.visuals = visuals.clone();
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(14.0, 7.0);
            style.spacing.interact_size.y = 32.0;
            style.text_styles = [
                (
                    TextStyle::Small,
                    FontId::new(11.5, FontFamily::Proportional),
                ),
                (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
                (
                    TextStyle::Button,
                    FontId::new(14.0, FontFamily::Proportional),
                ),
                (
                    TextStyle::Monospace,
                    FontId::new(13.0, FontFamily::Monospace),
                ),
                (TextStyle::Heading, FontId::new(30.0, bold_family())),
            ]
            .into();
        });
    }

    /// The site's nav bar: the mark and name, then each page as a plain lowercase word, the
    /// current one in yellow.
    fn render_top_bar(&mut self, ui: &mut egui::Ui, runtime: &UiRuntimeState) {
        ui.horizontal_centered(|ui| {
            shard_mark(ui, 26.0, TEXT);
            ui.add_space(2.0);
            ui.label(display("blackshard", 20.0));
            ui.add_space(30.0);
            for page in [
                Page::Dashboard,
                Page::Scan,
                Page::Quarantine,
                Page::Activity,
                Page::Settings,
            ] {
                let selected = self.page == page;
                let response = ui
                    .add(
                        egui::Button::new(
                            RichText::new(page.title())
                                .size(17.0)
                                .extra_letter_spacing(17.0 * TRACKING)
                                .color(if selected { SIGNAL } else { TEXT }),
                        )
                        .frame(false),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                if response.has_focus() {
                    ui.painter().hline(
                        response.rect.x_range(),
                        response.rect.bottom(),
                        Stroke::new(1.0_f32, SIGNAL),
                    );
                }
                if response.clicked() {
                    self.page = page;
                }
                ui.add_space(8.0);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (label, color) = compact_health(runtime);
                status_mark(ui, &label, color);
            });
        });
    }

    fn render_notice(&mut self, ui: &mut egui::Ui) {
        let Some(notice) = &self.notice else {
            return;
        };
        let color = match notice.level {
            NoticeLevel::Information | NoticeLevel::Success => TEXT,
            NoticeLevel::Warning => ATTENTION,
            NoticeLevel::Error => ALARM,
        };
        let message = notice.message.clone();
        banner(ui, color, &message);
    }

    fn render_dashboard(&mut self, ui: &mut egui::Ui, runtime: &UiRuntimeState) {
        let (health, detail, color) = overall_health(runtime);
        // The userland self-test exercises the detection engine rather than kernel enforcement,
        // so it is just as runnable without a driver.
        let test_available = matches!(runtime.protection, ProtectionStatus::Active)
            && matches!(
                runtime.driver,
                DriverStatus::Connected | DriverStatus::NotRequired
            );
        let test_busy = matches!(
            runtime.protection_test,
            ProtectionTestStatus::Requested | ProtectionTestStatus::Running
        );

        // blackshard.dev's opening spread: a statement on the left, the shard on the right, one
        // white hairline between them. The shard takes the colour of the machine's state, so the
        // answer to "am I protected?" is visible from across the room.
        let (spread, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), 340.0),
            egui::Sense::hover(),
        );
        let middle = spread.center().x.round() + 0.5;
        ui.painter()
            .vline(middle, spread.y_range(), Stroke::new(1.0_f32, TEXT));
        let gutter = 36.0;
        let mut left = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(egui::Rect::from_min_max(
                    spread.min,
                    egui::pos2(middle - gutter, spread.max.y),
                ))
                .layout(Layout::top_down(Align::Center)),
        );
        let mut right = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(egui::Rect::from_min_max(
                    egui::pos2(middle + gutter, spread.min.y),
                    spread.max,
                ))
                .layout(Layout::top_down(Align::Center)),
        );

        left.add_space(56.0);
        left.label(display(&health, 34.0).color(color));
        left.add_space(12.0);
        left.add(
            egui::Label::new(RichText::new(&detail).size(15.0).color(TEXT)).halign(Align::Center),
        );
        // The attention line often repeats the reason already in the detail.
        if let Some(attention) = runtime
            .attention
            .as_ref()
            .filter(|attention| !detail.contains(attention.as_str()))
        {
            left.add_space(6.0);
            left.add(
                egui::Label::new(RichText::new(attention).size(13.0).color(ATTENTION))
                    .halign(Align::Center),
            );
        }
        left.add_space(28.0);
        // The site's yellow italic line, here the one thing worth doing from this page.
        let test = left
            .add_enabled(
                test_available && !test_busy,
                egui::Button::new(
                    RichText::new("run the harmless protection test")
                        .italics()
                        .size(17.0)
                        .color(SIGNAL),
                )
                .frame(false),
            )
            .on_hover_text("Checks detection and blocking end to end with a harmless file")
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if test.has_focus() {
            left.painter().hline(
                test.rect.x_range(),
                test.rect.bottom(),
                Stroke::new(1.0_f32, SIGNAL),
            );
        }
        let (test_status, test_color) = match &runtime.protection_test {
            ProtectionTestStatus::Idle if !test_available => {
                ("available once protection is active".to_owned(), MUTED)
            }
            ProtectionTestStatus::Idle => ("not run yet".to_owned(), MUTED),
            ProtectionTestStatus::Requested => ("queued".to_owned(), MUTED),
            ProtectionTestStatus::Running => ("testing the protection path".to_owned(), MUTED),
            ProtectionTestStatus::Passed(detail) => (format!("passed. {detail}"), OK),
            ProtectionTestStatus::Failed(error) => (format!("failed. {error}"), ALARM),
        };
        left.horizontal(|ui| {
            if test_busy {
                ui.spinner();
            }
        });
        left.add(
            egui::Label::new(RichText::new(test_status).size(13.0).color(test_color))
                .halign(Align::Center),
        );
        if test.clicked() {
            if let Ok(mut state) = self.runtime.lock() {
                state.protection_test = ProtectionTestStatus::Requested;
            }
        }

        right.add_space(40.0);
        shard_mark(&mut right, 150.0, color);
        right.add_space(26.0);
        fact(
            &mut right,
            runtime.realtime_scanned_files,
            "files checked as they opened",
            TEXT,
        );
        fact(
            &mut right,
            runtime.realtime_blocked_files,
            "threats blocked",
            if runtime.realtime_blocked_files > 0 {
                ALARM
            } else {
                TEXT
            },
        );
        fact(
            &mut right,
            self.quarantine_records.len() as u64,
            "files in quarantine",
            TEXT,
        );
        if runtime.realtime_bypassed_requests > 0 {
            fact(
                &mut right,
                runtime.realtime_bypassed_requests,
                "checks skipped under load",
                ATTENTION,
            );
        }

        let mut scan_request = None;
        section(ui, |ui| {
            section_title(
                ui,
                "scan now",
                "scans run at low priority, so you can keep working.",
            );
            let choices = [
                (
                    "quick scan",
                    "where malware lands, and every program that is running",
                    Some(ScanRequestKind::Quick),
                ),
                (
                    "full scan",
                    "every local drive. this one takes a while",
                    Some(ScanRequestKind::Full),
                ),
                ("choose what to scan", "one file or folder", None),
            ];
            egui::Grid::new("dashboard_scans")
                .spacing(egui::vec2(18.0, 8.0))
                .show(ui, |ui| {
                    for (label, detail, kind) in choices {
                        if bracket_button(ui, label, TEXT, true).clicked() {
                            match kind {
                                Some(kind) => scan_request = Some(kind),
                                None => self.page = Page::Scan,
                            }
                        }
                        ui.label(RichText::new(detail).color(MUTED));
                        ui.end_row();
                    }
                });
        });
        if let Some(kind) = scan_request {
            self.start_scan(kind);
        }

        ui.columns(2, |columns| {
            section(&mut columns[0], |ui| {
                section_title(ui, "protection", "what is actually running right now");
                health_row(
                    ui,
                    "real-time engine",
                    protection_label(&runtime.protection),
                );
                health_row(ui, "kernel filter", driver_label(&runtime.driver));
                if let (Some(version), Some(age)) =
                    (&runtime.freshclam_version, runtime.freshclam_age_hours)
                {
                    health_row(
                        ui,
                        "clamav signatures",
                        (format!("version {version}, {age}h old"), OK),
                    );
                } else {
                    health_row(ui, "definitions", definition_label(&runtime.definitions));
                }
            });
            section(&mut columns[1], |ui| {
                section_title(ui, "this build", "who made it, and who has checked it");
                health_row(ui, "package", trust_label(&runtime.build_trust));
                health_row(
                    ui,
                    "independent testing",
                    certification_label(&runtime.certification),
                );
                ui.label(
                    RichText::new(
                        "a signature proves who built this copy. it says nothing about how well \
                         it detects malware.",
                    )
                    .size(12.0)
                    .color(MUTED),
                );
            });
        });

        section(ui, |ui| {
            section_title(ui, "recent activity", "newest first");
            if self.activity.is_empty() {
                empty_state(ui, "nothing has happened yet. blackshard writes every detection, scan and change here.");
            } else {
                for event in self.activity.iter().take(5) {
                    activity_row(ui, event);
                }
                if self.activity.len() > 5
                    && bracket_button(ui, "all activity", TEXT, true).clicked()
                {
                    self.page = Page::Activity;
                }
            }
        });
    }

    fn render_scan(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "scan",
            "check where malware usually lands, every drive, or one exact file.",
        );

        let running = self
            .scan_job
            .as_ref()
            .is_some_and(|job| !job.snapshot().is_finished());
        let mut requested = None;
        section(ui, |ui| {
            let choices = [
                (
                    "quick scan",
                    "where malware lands, plus every running program. a few minutes",
                    ScanRequestKind::Quick,
                ),
                (
                    "full scan",
                    "every local drive. this can take a long time",
                    ScanRequestKind::Full,
                ),
            ];
            egui::Grid::new("scan_choices")
                .spacing(egui::vec2(18.0, 8.0))
                .show(ui, |ui| {
                    for (label, detail, kind) in choices {
                        if bracket_button(ui, label, TEXT, !running).clicked() {
                            requested = Some(kind);
                        }
                        ui.label(RichText::new(detail).color(MUTED));
                        ui.end_row();
                    }
                });
            ui.add_space(14.0);
            ui.label(RichText::new("or one file or folder").color(TEXT));
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 120.0, 34.0],
                    egui::TextEdit::singleline(&mut self.custom_scan_path)
                        .hint_text(r"C:\Users\you\Downloads\sample.exe"),
                );
                if bracket_button(ui, "scan it", TEXT, !running).clicked() {
                    requested = Some(ScanRequestKind::Custom { roots: Vec::new() });
                }
            });
        });
        if let Some(kind) = requested {
            if matches!(kind, ScanRequestKind::Custom { .. }) {
                self.start_custom_scan();
            } else {
                self.start_scan(kind);
            }
        }

        let snapshot = self.scan_job.as_ref().map(ServiceScanJob::snapshot);
        let mut cancel_requested = false;
        section(ui, |ui| {
            let Some(progress) = snapshot.as_ref() else {
                section_title(ui, "progress", "");
                empty_state(
                    ui,
                    "no scan has run since blackshard opened. start one above.",
                );
                return;
            };

            let (phase, phase_color) = scan_phase_label(progress.phase);
            ui.horizontal(|ui| {
                ui.label(display(progress.kind.display_name().to_lowercase(), 20.0));
                status_mark(ui, phase, phase_color);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format_duration(Duration::from_millis(
                            progress.elapsed_millis,
                        )))
                        .color(MUTED),
                    );
                });
            });
            ui.add_space(8.0);

            let fraction = if progress.discovered_files > 0 {
                (progress.scanned_files as f32 / progress.discovered_files as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            ui.add(
                egui::ProgressBar::new(fraction)
                    .desired_width(ui.available_width())
                    .desired_height(6.0)
                    .corner_radius(egui::CornerRadius::ZERO)
                    .fill(SIGNAL),
            );
            ui.label(
                RichText::new(format!(
                    "{} of {} files",
                    group_digits(progress.scanned_files),
                    group_digits(progress.discovered_files)
                ))
                .color(TEXT),
            );
            if let Some(path) = &progress.current_path {
                ui.add(egui::Label::new(RichText::new(path).size(12.0).color(MUTED)).truncate());
            }
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                metric(ui, "clean", progress.clean_files, TEXT);
                metric(ui, "suspicious", progress.suspicious_files, ATTENTION);
                metric(ui, "malicious", progress.malicious_files, ALARM);
                metric(ui, "quarantined", progress.quarantined_files, TEXT);
                metric(ui, "unreadable", progress.errors, MUTED);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !progress.is_finished()
                        && bracket_button(ui, "stop scan", ALARM, true).clicked()
                    {
                        cancel_requested = true;
                    }
                });
            });
            if let Some(failure) = &progress.failure {
                ui.add_space(6.0);
                ui.colored_label(ALARM, failure);
            }
        });
        if cancel_requested {
            if let Some(job) = &self.scan_job {
                job.cancel();
            }
        }

        if let Some(progress) = snapshot {
            if !progress.findings.is_empty() {
                section(ui, |ui| {
                    section_title(ui, "findings", "newest first");
                    for finding in progress.findings.iter().rev() {
                        finding_row(ui, finding);
                    }
                });
            }
        }
    }

    fn render_quarantine(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "quarantine",
            "isolated files are encrypted here and cannot run. restore only what you trust.",
        );
        ui.horizontal(|ui| {
            if bracket_button(ui, "refresh", TEXT, true).clicked() {
                self.refresh_persistent_views();
            }
            ui.label(
                RichText::new(format!(
                    "{} {}",
                    self.quarantine_records.len(),
                    if self.quarantine_records.len() == 1 {
                        "file"
                    } else {
                        "files"
                    }
                ))
                .color(MUTED),
            );
        });

        if self.quarantine_records.is_empty() {
            section(ui, |ui| {
                empty_state(
                    ui,
                    "nothing is in quarantine. files blackshard isolates will wait here.",
                )
            });
            return;
        }

        let mut confirmation = None;
        for record in &self.quarantine_records {
            let busy = self.busy_quarantine.contains(&record.id);
            section(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(bold(&record.threat_name).size(16.0).color(ALARM));
                        ui.label(RichText::new(&record.original_path).color(TEXT));
                        ui.label(
                            RichText::new(format!(
                                "isolated {}, {}, risk {}",
                                record
                                    .quarantined_at
                                    .with_timezone(&Local)
                                    .format("%Y-%m-%d %H:%M"),
                                format_bytes(record.size),
                                record.risk_score
                            ))
                            .size(12.0)
                            .color(MUTED),
                        );
                        if record.state == IsolationState::SourceStillPresent {
                            status_mark(ui, "the original file is still on disk", ALARM);
                        }
                        ui.label(
                            RichText::new(format!("sha-256 {}", record.sha256))
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if bracket_button(ui, "delete", ALARM, !busy).clicked() {
                            confirmation = Some(Confirmation::Delete(record.clone()));
                        }
                        if bracket_button(ui, "restore", TEXT, !busy).clicked() {
                            confirmation = Some(Confirmation::Restore(record.clone()));
                        }
                        if busy {
                            ui.spinner();
                        }
                    });
                });
            });
        }
        if confirmation.is_some() {
            self.confirmation = confirmation;
        }
    }

    fn render_activity(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "activity",
            "everything blackshard did on this machine, newest first.",
        );
        ui.horizontal(|ui| {
            if bracket_button(ui, "refresh", TEXT, true).clicked() {
                self.refresh_persistent_views();
            }
            if bracket_button(ui, "clear history", ALARM, !self.activity.is_empty()).clicked() {
                self.confirmation = Some(Confirmation::ClearActivity);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(format!("{} events", self.activity.len())).color(MUTED));
            });
        });
        section(ui, |ui| {
            if self.activity.is_empty() {
                empty_state(
                    ui,
                    "nothing has happened yet. detections, scans and changes appear here.",
                );
            } else {
                for event in &self.activity {
                    activity_row(ui, event);
                }
            }
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui, runtime: &UiRuntimeState) {
        page_heading(
            ui,
            "settings",
            "how blackshard watches, responds and updates.",
        );
        let mut changed = false;
        let mut update_requested = false;

        section(ui, |ui| {
            section_title(
                ui,
                "protection",
                "what you choose here; the top bar shows what is running",
            );
            changed |= ui
                .checkbox(
                    &mut self.settings.real_time_protection,
                    "check files as they are opened and run",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.automatic_quarantine,
                    "move confirmed malware to quarantine automatically",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.ransomware_protection,
                    "watch for programs encrypting your documents",
                )
                .changed();
            ui.add_enabled_ui(self.settings.ransomware_protection, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(24.0);
                    changed |= ui
                        .checkbox(
                            &mut self.settings.ransomware_block_mode,
                            "stop them, and quarantine unsigned ones (needs the kernel filter)",
                        )
                        .changed();
                });
            });
            changed |= ui
                .checkbox(
                    &mut self.settings.notify_on_detection,
                    "show a windows notification when a threat is stopped",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.scan_archives,
                    "look inside zip and office files",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.scan_network_drives,
                    "include network drives in full scans",
                )
                .changed();
        });

        section(ui, |ui| {
            section_title(ui, "performance", "keep scans out of your way");
            changed |= ui
                .checkbox(
                    &mut self.settings.low_resource_mode,
                    "low-resource mode (recommended)",
                )
                .changed();
            ui.horizontal(|ui| {
                ui.label("scan workers");
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut self.settings.worker_count)
                            .range(1..=16)
                            .speed(1),
                    )
                    .changed();
            });
            ui.horizontal(|ui| {
                ui.label("skip files larger than");
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut self.settings.max_file_size_mb)
                            .range(1..=4_096)
                            .suffix(" MiB"),
                    )
                    .changed();
            });
        });

        section(ui, |ui| {
            section_title(
                ui,
                "updates",
                "only signed, unexpired definitions newer than the installed ones are accepted",
            );
            ui.horizontal(|ui| {
                ui.label("check every");
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut self.settings.definition_update_interval_hours)
                            .range(1..=24)
                            .suffix(" hours"),
                    )
                    .changed();
                if bracket_button(ui, "check now", TEXT, true).clicked() {
                    update_requested = true;
                }
            });
            let (definition, color) = definition_label(&runtime.definitions);
            ui.colored_label(color, definition);
        });

        section(ui, |ui| {
            section_title(
                ui,
                "exclusions",
                "blackshard never looks inside these. add only paths you fully trust.",
            );
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 90.0, 34.0],
                    egui::TextEdit::singleline(&mut self.exclusion_input)
                        .hint_text(r"C:\trusted\path"),
                );
                if bracket_button(ui, "add", TEXT, true).clicked() {
                    let value = self.exclusion_input.trim().trim_matches('"');
                    if !value.is_empty() {
                        self.settings.add_exclusion(PathBuf::from(value));
                        self.exclusion_input.clear();
                        changed = true;
                    }
                }
            });
            let mut remove_index = None;
            for (index, exclusion) in self.settings.exclusions.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(exclusion.display().to_string()).size(13.0));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if bracket_button(ui, "remove", ALARM, true).clicked() {
                            remove_index = Some(index);
                        }
                    });
                });
            }
            if let Some(index) = remove_index {
                self.settings.exclusions.remove(index);
                changed = true;
            }
        });

        section(ui, |ui| {
            section_title(ui, "about this build", "");
            health_row(ui, "version", (runtime.engine_version.clone(), TEXT));
            health_row(ui, "package", trust_label(&runtime.build_trust));
            health_row(
                ui,
                "independent testing",
                certification_label(&runtime.certification),
            );
            ui.label(
                RichText::new(
                    "blackshard only claims independent certification when a named lab has \
                     granted it. development builds always say so.",
                )
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("phase 1: the windows client. free, forever.")
                    .italics()
                    .color(SIGNAL),
            );
        });

        if changed {
            self.queue_settings_save();
        }
        if update_requested {
            if let Ok(mut shared) = self.runtime.lock() {
                shared.update_check_requested = true;
            }
            self.notice = Some(Notice {
                level: NoticeLevel::Information,
                message: "checking for updates. the definitions line will show the result."
                    .to_owned(),
                created: Instant::now(),
            });
        }
    }

    fn render_confirmation(&mut self, ctx: &egui::Context) {
        let Some(confirmation) = self.confirmation.clone() else {
            return;
        };
        let (title, message, confirm_label, confirm_color) = match &confirmation {
            Confirmation::Restore(record) => (
                "restore this file?",
                format!(
                    "Restore {} to {}? The file may still be dangerous and can be isolated again by real-time protection.",
                    record.threat_name,
                    record.original_path
                ),
                "restore",
                ATTENTION,
            ),
            Confirmation::Delete(record) => (
                "delete this file for good?",
                format!(
                    "Permanently delete the quarantined copy of {}? This cannot be undone.",
                    record.original_path
                ),
                "delete permanently",
                ALARM,
            ),
            Confirmation::ClearActivity => (
                "clear activity history?",
                "Delete the local activity history? This does not change quarantine or protection settings."
                    .to_owned(),
                "clear history",
                ALARM,
            ),
        };

        let mut accepted = false;
        let mut cancelled = false;
        egui::Window::new(title)
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .fixed_size(egui::vec2(480.0, 0.0))
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .stroke(Stroke::new(1.0_f32, TEXT))
                    .inner_margin(egui::Margin::same(24)),
            )
            .show(ctx, |ui| {
                ui.label(display(title, 22.0));
                ui.add_space(8.0);
                ui.label(message);
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    if bracket_button(ui, confirm_label, confirm_color, true).clicked() {
                        accepted = true;
                    }
                    if bracket_button(ui, "cancel", TEXT, true).clicked()
                        || ui.input(|input| input.key_pressed(egui::Key::Escape))
                    {
                        cancelled = true;
                    }
                });
            });

        if accepted {
            match confirmation {
                Confirmation::Restore(record) => {
                    self.begin_quarantine_operation(QuarantineOperation::Restore, record.id)
                }
                Confirmation::Delete(record) => {
                    self.begin_quarantine_operation(QuarantineOperation::Delete, record.id)
                }
                Confirmation::ClearActivity => match self.client.clear_activity() {
                    Ok(_) => {
                        self.activity.clear();
                        self.notice = Some(Notice {
                            level: NoticeLevel::Success,
                            message: "activity history cleared.".to_owned(),
                            created: Instant::now(),
                        });
                    }
                    Err(error) if error.code == RpcErrorCode::AccessDenied => {
                        self.notice = Some(match elevation::request_clear_activity() {
                            Ok(()) => Notice {
                                level: NoticeLevel::Information,
                                message: "approve the windows administrator prompt to clear the activity history.".to_owned(),
                                created: Instant::now(),
                            },
                            Err(error) => Notice {
                                level: NoticeLevel::Error,
                                message: format!("administrator approval could not be requested: {error}"),
                                created: Instant::now(),
                            },
                        });
                    }
                    Err(error) => {
                        self.notice = Some(Notice {
                            level: NoticeLevel::Error,
                            message: format!("activity history could not be cleared: {error}"),
                            created: Instant::now(),
                        });
                    }
                },
            }
            self.confirmation = None;
        } else if cancelled {
            self.confirmation = None;
        }
    }
}

impl Drop for BlackshardApp {
    fn drop(&mut self) {
        if self.settings_dirty {
            let _ = self.client.save_settings(self.settings.clone());
        }
    }
}

impl eframe::App for BlackshardApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        self.poll_background_work();
        let runtime = self.runtime_snapshot();

        if should_show_loading_screen(&runtime) {
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(BG))
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space((ui.available_height() / 2.0 - 110.0).max(0.0));
                        shard_mark(ui, 120.0, TEXT);
                        ui.add_space(22.0);
                        let status_text = match &runtime.readiness {
                            Some(crate::readiness::ReadinessState::LoadingSettings) => {
                                "loading settings"
                            }
                            Some(
                                crate::readiness::ReadinessState::LoadingDefinitions
                                | crate::readiness::ReadinessState::LoadingFreshClam,
                            ) => "loading definitions",
                            Some(crate::readiness::ReadinessState::StartingDetectionWorkers) => {
                                "starting detection"
                            }
                            Some(crate::readiness::ReadinessState::ConnectingDriver) => {
                                "connecting to the kernel filter"
                            }
                            Some(crate::readiness::ReadinessState::ValidatingProtocol) => {
                                "checking the protection channel"
                            }
                            _ => "starting blackshard",
                        };
                        ui.label(
                            RichText::new(status_text)
                                .italics()
                                .size(17.0)
                                .color(SIGNAL),
                        );
                    });
                });
            ctx.request_repaint_after(Duration::from_millis(150));
            return;
        }

        egui::Panel::top("blackshard_top")
            .exact_size(64.0)
            .frame(
                egui::Frame::NONE
                    .fill(BAR)
                    .inner_margin(egui::Margin::symmetric(24, 0)),
            )
            .show(ui, |ui| self.render_top_bar(ui, &runtime));

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // A centred measure, as the site's columns are; wide windows gain margin
                        // rather than line length.
                        let width = ui.available_width().min(980.0);
                        let margin = ((ui.available_width() - width) / 2.0).max(0.0);
                        ui.horizontal(|ui| {
                            ui.add_space(margin);
                            ui.vertical(|ui| {
                                ui.set_width(width - 48.0);
                                ui.add_space(24.0);
                                self.render_notice(ui);
                                // With the service down every read fails the same way, and the
                                // status page already says so in plain words.
                                if let Some(error) = self.persistent_error.clone().filter(|_| {
                                    !matches!(runtime.protection, ProtectionStatus::Unavailable(_))
                                }) {
                                    banner(ui, ALARM, &error);
                                }
                                match self.page {
                                    Page::Dashboard => self.render_dashboard(ui, &runtime),
                                    Page::Scan => self.render_scan(ui),
                                    Page::Quarantine => self.render_quarantine(ui),
                                    Page::Activity => self.render_activity(ui),
                                    Page::Settings => self.render_settings(ui, &runtime),
                                }
                                ui.add_space(32.0);
                            });
                        });
                    });
            });

        self.render_confirmation(ctx);
        let scan_running = self
            .scan_job
            .as_ref()
            .is_some_and(|job| !job.snapshot().is_finished());
        let operation_running = !self.busy_quarantine.is_empty();
        ctx.request_repaint_after(if scan_running || operation_running {
            Duration::from_millis(150)
        } else {
            Duration::from_secs(1)
        });
    }
}

fn should_show_loading_screen(runtime: &UiRuntimeState) -> bool {
    use crate::readiness::ReadinessState;
    if let Some(readiness) = &runtime.readiness {
        matches!(
            readiness,
            ReadinessState::Starting
                | ReadinessState::LoadingSettings
                | ReadinessState::LoadingDefinitions
                | ReadinessState::LoadingFreshClam
                | ReadinessState::StartingDetectionWorkers
                | ReadinessState::ConnectingDriver
                | ReadinessState::ValidatingProtocol
        )
    } else {
        matches!(runtime.protection, ProtectionStatus::Starting)
    }
}

/// Loads JetBrains Mono, the site's typeface, ahead of egui's own fonts, which stay behind as
/// fallbacks for glyphs it lacks, such as emoji in file names.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for (name, bytes) in [
        (
            REGULAR_FONT,
            include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf").as_slice(),
        ),
        (
            BOLD_FONT,
            include_bytes!("../assets/fonts/JetBrainsMono-Bold.ttf").as_slice(),
        ),
    ] {
        fonts.font_data.insert(
            name.to_owned(),
            Arc::new(egui::FontData::from_static(bytes)),
        );
    }
    let fallbacks = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .insert(0, REGULAR_FONT.to_owned());
    }
    fonts.families.insert(
        bold_family(),
        std::iter::once(BOLD_FONT.to_owned())
            .chain(fallbacks)
            .collect(),
    );
    ctx.set_fonts(fonts);
}

/// egui has no font weights, so bold is its own family.
fn bold_family() -> FontFamily {
    FontFamily::Name(BOLD_FONT.into())
}

fn bold(text: impl Into<String>) -> RichText {
    RichText::new(text).family(bold_family())
}

/// Display type: bold and tracked in, like the site's headings.
fn display(text: impl Into<String>, size: f32) -> RichText {
    bold(text)
        .size(size)
        .extra_letter_spacing(size * TRACKING)
        .color(TEXT)
}

/// The blackshard mark, drawn rather than loaded so it can take the colour of the machine's
/// state. Bars on a 7 by 9 grid, traced from the site's logo: `(column, top row, bottom row)`.
fn shard_mark(ui: &mut egui::Ui, height: f32, color: Color32) -> egui::Response {
    const BARS: [(u8, u8, u8); 10] = [
        (0, 6, 9),
        (1, 3, 6),
        (1, 7, 9),
        (2, 0, 3),
        (2, 7, 8),
        (3, 1, 4),
        (3, 6, 8),
        (4, 3, 7),
        (5, 4, 6),
        (6, 5, 6),
    ];
    let row = height / 9.0;
    let column = row * 1.01;
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(column * 7.0, height), egui::Sense::hover());
    let gap = (column * 0.06).max(1.0);
    for (x, top, bottom) in BARS {
        let min = rect.min + egui::vec2(f32::from(x) * column, f32::from(top) * row);
        let max =
            rect.min + egui::vec2((f32::from(x) + 1.0) * column - gap, f32::from(bottom) * row);
        ui.painter()
            .rect_filled(egui::Rect::from_min_max(min, max), 0.0, color);
    }
    response
}

/// Text between two solid bars, after the roadmap boxes on blackshard.dev. Hover and keyboard
/// focus fill it with the nav bar's grey; focus also underlines it in yellow.
fn bracket_button(ui: &mut egui::Ui, label: &str, color: Color32, enabled: bool) -> egui::Response {
    let text_color = if enabled { color } else { MUTED };
    let galley = egui::WidgetText::from(RichText::new(label).size(14.0).color(text_color))
        .into_galley(
            ui,
            Some(egui::TextWrapMode::Extend),
            f32::INFINITY,
            egui::TextStyle::Button,
        );
    let padding = egui::vec2(16.0, 7.0);
    let (rect, response) = ui.allocate_exact_size(
        galley.size() + 2.0 * padding,
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, label));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if enabled && (response.hovered() || response.has_focus()) {
            painter.rect_filled(rect, 0.0, BAR);
        }
        let bar = Stroke::new(2.0_f32, if enabled { color } else { RULE });
        painter.vline(rect.left() + 1.0, rect.y_range(), bar);
        painter.vline(rect.right() - 1.0, rect.y_range(), bar);
        if response.has_focus() {
            painter.hline(rect.x_range(), rect.bottom(), Stroke::new(1.0_f32, SIGNAL));
        }
        painter.galley(rect.min + padding, galley, text_color);
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A short status, led by one bar of the shard mark in the status colour.
fn status_mark(ui: &mut egui::Ui, label: &str, color: Color32) -> egui::Response {
    let galley = egui::WidgetText::from(bold(label).size(13.0).color(color)).into_galley(
        ui,
        Some(egui::TextWrapMode::Extend),
        f32::INFINITY,
        egui::TextStyle::Body,
    );
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(13.0 + galley.size().x, galley.size().y.max(16.0)),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(
        egui::Rect::from_center_size(
            egui::pos2(rect.left() + 2.5, rect.center().y),
            egui::vec2(5.0, 14.0),
        ),
        0.0,
        color,
    );
    painter.galley(
        egui::pos2(rect.left() + 13.0, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    response
}

/// A message across the page, marked by a bar in its colour rather than boxed.
fn banner(ui: &mut egui::Ui, color: Color32, message: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(3.0, 22.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 0.0, color);
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(message).color(color)).wrap());
    });
    ui.add_space(14.0);
}

fn page_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(display(title, 34.0));
    ui.label(RichText::new(subtitle).size(15.0).color(MUTED));
    ui.add_space(18.0);
}

fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(display(title, 18.0));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).size(13.0).color(MUTED));
    }
    ui.add_space(6.0);
}

/// One block of a page. The site separates things with space and hairlines, never boxes.
fn section<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.add_space(10.0);
    let top = ui.cursor().top();
    ui.painter().hline(
        ui.available_rect_before_wrap().x_range(),
        top,
        Stroke::new(1.0_f32, RULE),
    );
    egui::Frame::NONE
        .inner_margin(egui::Margin {
            left: 0,
            right: 0,
            top: 18,
            bottom: 8,
        })
        .show(ui, add_contents)
        .inner
}

/// One line of the status page's tally: the number in bold, then what it counts.
fn fact(ui: &mut egui::Ui, value: u64, words: &str, color: Color32) {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        &group_digits(value),
        0.0,
        egui::TextFormat::simple(FontId::new(17.0, bold_family()), color),
    );
    job.append(
        words,
        10.0,
        egui::TextFormat::simple(FontId::new(15.0, FontFamily::Proportional), MUTED),
    );
    ui.label(job);
}

fn metric(ui: &mut egui::Ui, label: &str, value: u64, color: Color32) {
    ui.label(bold(group_digits(value)).color(color));
    ui.label(RichText::new(label).color(MUTED));
    ui.add_space(10.0);
}

fn health_row(ui: &mut egui::Ui, label: &str, value: (String, Color32)) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            // Truncated, with the whole value on hover: a long reason laid out right to left
            // would otherwise grow leftwards out of its column.
            ui.add(egui::Label::new(RichText::new(&value.0).color(value.1)).truncate())
                .on_hover_text(&value.0);
        });
    });
}

fn activity_row(ui: &mut egui::Ui, event: &SecurityEvent) {
    let (kind, color) = event_kind_label(&event.kind);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(
                event
                    .timestamp
                    .with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            )
            .size(12.0)
            .color(MUTED),
        );
        status_mark(ui, kind, color);
        ui.label(&event.summary);
    });
    if event.path.is_some() || event.threat_name.is_some() || event.details.is_some() {
        ui.horizontal_wrapped(|ui| {
            ui.add_space(156.0);
            if let Some(threat) = &event.threat_name {
                ui.label(bold(threat).color(ALARM));
            }
            if let Some(path) = &event.path {
                ui.label(
                    RichText::new(path.display().to_string())
                        .size(12.0)
                        .color(MUTED),
                );
            }
            if let Some(details) = &event.details {
                ui.label(RichText::new(details).size(12.0).color(MUTED));
            }
        });
    }
    ui.add_space(4.0);
}

fn finding_row(ui: &mut egui::Ui, finding: &ScanFindingView) {
    let (verdict, color) = match finding.verdict {
        DetectionVerdictView::Clean => ("clean", OK),
        DetectionVerdictView::Suspicious => ("suspicious", ATTENTION),
        DetectionVerdictView::Malicious => ("malicious", ALARM),
        DetectionVerdictView::Error => ("could not scan", PENDING),
    };
    ui.horizontal_wrapped(|ui| {
        status_mark(ui, verdict, color);
        ui.label(
            bold(
                finding
                    .threat_name
                    .as_deref()
                    .unwrap_or("unclassified finding"),
            )
            .color(color),
        );
        ui.label(
            RichText::new(format!(
                "risk {}, confidence {}%",
                finding.risk_score, finding.confidence
            ))
            .size(12.0)
            .color(MUTED),
        );
    });
    ui.label(RichText::new(&finding.path).size(13.0).color(TEXT));
    if let Some(state) = finding.quarantine_state {
        ui.colored_label(
            if state == IsolationState::Isolated {
                OK
            } else {
                ALARM
            },
            if state == IsolationState::Isolated {
                "moved to quarantine"
            } else {
                "an encrypted copy is in quarantine, but the original is still on disk"
            },
        );
    }
    if let Some(error) = &finding.action_error {
        ui.colored_label(ALARM, format!("could not remove it: {error}"));
    }
    if let Some(error) = &finding.analysis_error {
        ui.colored_label(MUTED, format!("note: {error}"));
    }
    ui.add_space(10.0);
}

fn empty_state(ui: &mut egui::Ui, message: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(message).italics().color(MUTED));
    ui.add_space(10.0);
}

/// 12402 as "12,402".
fn group_digits(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn compact_health(runtime: &UiRuntimeState) -> (String, Color32) {
    match (&runtime.protection, &runtime.driver) {
        (ProtectionStatus::Active, DriverStatus::Connected | DriverStatus::NotRequired) => {
            ("protected".to_owned(), OK)
        }
        (ProtectionStatus::Paused, _) => ("paused".to_owned(), ATTENTION),
        (ProtectionStatus::Unavailable(_), _) => ("not protected".to_owned(), ALARM),
        (_, DriverStatus::Disconnected(_))
        | (_, DriverStatus::NotInstalled)
        | (_, DriverStatus::Error(_)) => ("limited".to_owned(), ALARM),
        (ProtectionStatus::Starting, _) | (_, DriverStatus::Checking) => {
            ("checking".to_owned(), ATTENTION)
        }
        _ => ("limited".to_owned(), ALARM),
    }
}

fn overall_health(runtime: &UiRuntimeState) -> (String, String, Color32) {
    match (&runtime.protection, &runtime.driver) {
        (ProtectionStatus::Active, DriverStatus::Connected) => (
            "you're protected".to_owned(),
            "blackshard checks every file as it is opened or run, from inside the kernel."
                .to_owned(),
            OK,
        ),
        // Real protection, narrower than the kernel tier. The scope is stated rather than rounded
        // up, so nobody believes they have file system coverage they do not have.
        (ProtectionStatus::Active, DriverStatus::NotRequired) => (
            "you're protected".to_owned(),
            "scripts and macros are checked through AMSI as they run, and scans and quarantine work. installing the signed driver adds checks on every file."
                .to_owned(),
            OK,
        ),
        (ProtectionStatus::Paused, _) => (
            "protection is paused".to_owned(),
            "files are not checked as they open. you can still scan by hand.".to_owned(),
            ATTENTION,
        ),
        (ProtectionStatus::Unavailable(reason), _) => (
            "not protected".to_owned(),
            reason.clone(),
            ALARM,
        ),
        (_, DriverStatus::Disconnected(reason)) | (_, DriverStatus::Error(reason)) => (
            "limited protection".to_owned(),
            format!("the kernel filter is not connected, so files are not checked as they open: {reason}"),
            ALARM,
        ),
        (_, DriverStatus::NotInstalled) => (
            "limited protection".to_owned(),
            "the kernel filter is installed but did not load, so files are not checked as they open."
                .to_owned(),
            ALARM,
        ),
        (ProtectionStatus::Degraded(reason), _) => (
            "limited protection".to_owned(),
            format!("part of the engine is not working: {reason}"),
            ATTENTION,
        ),
        (ProtectionStatus::Starting, _) | (_, DriverStatus::Checking) => (
            "checking protection".to_owned(),
            "blackshard is checking the engine and the kernel filter.".to_owned(),
            ATTENTION,
        ),
    }
}

fn protection_label(status: &ProtectionStatus) -> (String, Color32) {
    match status {
        ProtectionStatus::Starting => ("starting".to_owned(), ATTENTION),
        ProtectionStatus::Active => ("running".to_owned(), OK),
        ProtectionStatus::Paused => ("paused".to_owned(), ATTENTION),
        ProtectionStatus::Degraded(reason) => (format!("degraded: {reason}"), ATTENTION),
        ProtectionStatus::Unavailable(reason) => (format!("stopped: {reason}"), ALARM),
    }
}

fn driver_label(status: &DriverStatus) -> (String, Color32) {
    match status {
        DriverStatus::Checking => ("checking".to_owned(), ATTENTION),
        DriverStatus::Connected => ("connected".to_owned(), OK),
        DriverStatus::Disconnected(reason) => (format!("disconnected: {reason}"), ALARM),
        DriverStatus::NotRequired => (
            "not installed; scripts covered by AMSI".to_owned(),
            ATTENTION,
        ),
        DriverStatus::NotInstalled => ("did not load".to_owned(), ALARM),
        DriverStatus::Error(reason) => (format!("error: {reason}"), ALARM),
    }
}

fn trust_label(status: &BuildTrustStatus) -> (String, Color32) {
    match status {
        BuildTrustStatus::Checking => ("checking".to_owned(), ATTENTION),
        BuildTrustStatus::AuthenticodeVerified { publisher } => {
            (format!("signed by {publisher}"), OK)
        }
        BuildTrustStatus::UnsignedDevelopmentBuild => {
            ("unsigned development build".to_owned(), ATTENTION)
        }
        BuildTrustStatus::VerificationFailed(reason) => {
            (format!("signature invalid: {reason}"), ALARM)
        }
    }
}

fn certification_label(status: &CertificationStatus) -> (String, Color32) {
    match status {
        CertificationStatus::NotEvaluated => ("not evaluated yet".to_owned(), MUTED),
        CertificationStatus::EvaluationInProgress => ("evaluation in progress".to_owned(), PENDING),
        CertificationStatus::IndependentlyCertified { authority } => {
            (format!("certified by {authority}"), OK)
        }
    }
}

fn definition_label(status: &DefinitionStatus) -> (String, Color32) {
    match status {
        DefinitionStatus::BuiltInOnly { version } => {
            (format!("built-in rules only ({version})"), ATTENTION)
        }
        DefinitionStatus::Updating { current_version } => (
            format!(
                "updating from {}",
                current_version.as_deref().unwrap_or("nothing installed")
            ),
            PENDING,
        ),
        DefinitionStatus::Current {
            version,
            expires_at,
        } => (
            format!(
                "{version}, good until {}",
                expires_at.with_timezone(&Local).format("%Y-%m-%d %H:%M")
            ),
            OK,
        ),
        DefinitionStatus::Stale {
            version,
            expired_at,
        } => (
            format!(
                "{version} expired {}",
                expired_at.with_timezone(&Local).format("%Y-%m-%d %H:%M")
            ),
            ATTENTION,
        ),
        DefinitionStatus::Failed(reason) => (format!("update failed: {reason}"), ALARM),
    }
}

fn scan_phase_label(phase: ScanPhaseView) -> (&'static str, Color32) {
    match phase {
        ScanPhaseView::Enumerating => ("finding files", PENDING),
        ScanPhaseView::Scanning => ("scanning", SIGNAL),
        ScanPhaseView::Cancelling => ("stopping", ATTENTION),
        ScanPhaseView::Completed => ("done", OK),
        ScanPhaseView::Cancelled => ("stopped", ATTENTION),
        ScanPhaseView::Failed => ("failed", ALARM),
    }
}

fn event_kind_label(kind: &EventKind) -> (&'static str, Color32) {
    match kind {
        EventKind::ProtectionStarted => ("protection", OK),
        EventKind::ProtectionStopped => ("protection", ATTENTION),
        EventKind::ScanStarted => ("scan", PENDING),
        EventKind::ScanCompleted => ("scan", OK),
        EventKind::Detection => ("detection", ALARM),
        EventKind::Quarantined => ("quarantine", ALARM),
        EventKind::QuarantineFailed => ("not removed", ALARM),
        EventKind::Restored => ("restored", ATTENTION),
        EventKind::UpdateInstalled => ("update", OK),
        EventKind::UpdateFailed => ("update", ALARM),
        EventKind::Error => ("error", ALARM),
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ui_state_never_claims_active_protection() {
        let state = UiRuntimeState::default();
        assert_ne!(compact_health(&state).0, "protected");
        assert_ne!(overall_health(&state).0, "you're protected");
    }

    #[test]
    fn active_label_requires_engine_and_filter() {
        let mut state = UiRuntimeState {
            protection: ProtectionStatus::Active,
            driver: DriverStatus::Disconnected("test".to_owned()),
            ..UiRuntimeState::default()
        };
        assert_eq!(compact_health(&state).0, "limited");

        state.driver = DriverStatus::Connected;
        assert_eq!(compact_health(&state).0, "protected");
    }

    #[test]
    fn known_driver_failure_overrides_starting_state() {
        let state = UiRuntimeState {
            driver: DriverStatus::NotInstalled,
            ..UiRuntimeState::default()
        };
        assert_eq!(compact_health(&state).0, "limited");
        assert_eq!(overall_health(&state).0, "limited protection");
    }

    #[test]
    fn a_userland_install_reads_as_protected_rather_than_broken() {
        let state = UiRuntimeState {
            protection: ProtectionStatus::Active,
            driver: DriverStatus::NotRequired,
            tier: crate::readiness::ProtectionTier::Userland,
            ..UiRuntimeState::default()
        };

        assert_eq!(compact_health(&state).0, "protected");
        let (headline, detail, colour) = overall_health(&state);
        assert_eq!(headline, "you're protected");
        assert_eq!(colour, OK);

        // The scope has to be stated, not rounded up to full file system coverage.
        assert!(detail.contains("AMSI"), "{detail}");
        assert!(detail.contains("signed driver"), "{detail}");
    }

    #[test]
    fn an_absent_driver_is_not_reported_in_red_when_none_is_installed() {
        assert_eq!(driver_label(&DriverStatus::NotRequired).1, ATTENTION);
        assert_eq!(driver_label(&DriverStatus::NotInstalled).1, ALARM);
    }

    #[test]
    fn byte_formatting_uses_binary_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
    }

    #[test]
    fn counts_are_grouped_in_thousands() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(12_402), "12,402");
        assert_eq!(group_digits(1_000_000), "1,000,000");
    }
}
