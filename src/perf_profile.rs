use std::sync::OnceLock;
use std::time::Instant;

static PERF_PHASES_ENABLED: OnceLock<bool> = OnceLock::new();

pub(crate) struct PerfPhase {
    operation: &'static str,
    phase: &'static str,
    message_id: Option<u32>,
    started: Option<Instant>,
}

impl PerfPhase {
    pub(crate) fn start(
        operation: &'static str,
        phase: &'static str,
        message_id: Option<u32>,
    ) -> Self {
        let started = perf_phases_enabled().then(Instant::now);
        Self {
            operation,
            phase,
            message_id,
            started,
        }
    }
}

impl Drop for PerfPhase {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let elapsed = started.elapsed();
        log::info!(
            target: "opendr::perf_profile",
            "perf_phase operation={} phase={} message_id={} elapsed_us={}",
            self.operation,
            self.phase,
            self.message_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            elapsed.as_micros()
        );
    }
}

fn perf_phases_enabled() -> bool {
    *PERF_PHASES_ENABLED.get_or_init(|| {
        std::env::var("OPENDR_PERF_PROFILE_PHASES")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_phase_can_be_created_without_logging_state() {
        let phase = PerfPhase::start("test", "phase", Some(1));
        if !perf_phases_enabled() {
            assert!(phase.started.is_none());
        }
    }
}
