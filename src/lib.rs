pub mod amsi;
pub mod archive;
pub mod atomic_file;
pub mod behavior;
pub mod config;
pub mod definitions;
pub mod detection;
pub mod driver_installer;
pub mod elevation;
pub mod engine;
pub mod history;
pub mod ipc;
pub mod notification_agent;
pub mod notifications;
#[cfg(windows)]
pub mod persistence;
pub mod quarantine;
pub mod readiness;
pub mod realtime;
pub mod rules;
pub mod scan_manager;
pub mod self_test;
pub mod service;
pub mod shards;
pub mod similarity;
pub mod trust;
pub mod ui;
pub mod update_client;
pub mod updater;
pub mod vba;
pub mod verdict_cache;

pub mod clamdb;

/// The product version, with the commit of the CI build that produced it when there is one
/// (`0.1.0+abc1234`), so a screenshot or bug report identifies the exact build.
pub fn product_version() -> String {
    match option_env!("BLACKSHARD_BUILD_ID") {
        Some(build) if !build.is_empty() => format!("{}+{build}", env!("CARGO_PKG_VERSION")),
        _ => env!("CARGO_PKG_VERSION").to_owned(),
    }
}
