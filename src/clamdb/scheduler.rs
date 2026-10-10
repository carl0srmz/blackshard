use log::{error, info};
use rand::RngExt;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use super::downloader;

/// Keeps the ClamAV definitions current in the background.
///
/// The first check runs at once, so the service can start on whatever it already has instead of
/// waiting for the mirror. After that it checks every four hours, or every fifteen minutes while
/// the machine has no definitions at all. A generation is only passed on when it differs from the
/// last one seen, since each hand-off makes the service reload every signature and discard its
/// verdict cache. A failed check is passed on too, since a service's log goes nowhere and the
/// health file is the only place it can be seen.
pub fn start_scheduler(
    program_data: PathBuf,
) -> Receiver<Result<downloader::ActiveDatabase, String>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut last_generation = downloader::active_database(&program_data)
            .ok()
            .map(|active| active.generation);
        let mut first = true;
        loop {
            if !first {
                let delay = next_check_delay(last_generation.is_some());
                info!(
                    "Definition updater: next check in {} seconds.",
                    delay.as_secs()
                );
                thread::sleep(delay);
            }
            first = false;

            match downloader::download_databases(&program_data) {
                Ok(active) if Some(active.generation) != last_generation => {
                    info!(
                        "Definition updater: activated generation {}.",
                        active.generation
                    );
                    last_generation = Some(active.generation);
                    let _ = sender.try_send(Ok(active));
                }
                Ok(_) => info!("Definition updater: definitions are already current."),
                Err(error) => {
                    error!("Definition update failed: {error}");
                    let _ = sender.try_send(Err(error.to_string()));
                }
            }
        }
    });
    receiver
}

/// The wait before the next check, with a sixteenth of it as jitter either way so that machines
/// started together do not reach the mirror together.
fn next_check_delay(has_definitions: bool) -> Duration {
    let base: u64 = if has_definitions {
        4 * 60 * 60
    } else {
        15 * 60
    };
    let spread = base / 16;
    let offset = rand::rng().random_range(0..=2 * spread);
    Duration::from_secs(base - spread + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_without_definitions_retries_sooner() {
        for _ in 0..100 {
            let empty = next_check_delay(false);
            let current = next_check_delay(true);
            assert!((14 * 60..=16 * 60).contains(&empty.as_secs()));
            assert!((225 * 60..=255 * 60).contains(&current.as_secs()));
        }
    }
}
