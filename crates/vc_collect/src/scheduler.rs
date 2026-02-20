//! Adaptive poll scheduler
//!
//! Dynamically adjusts poll intervals based on:
//! - Collector health (recent failures → backoff)
//! - Alert severity (active alerts → shorter intervals)
//! - Machine freshness (stale data → poll sooner)
//!
//! Includes quarantine for repeatedly failing collectors and
//! on-demand profiling burst support.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use vc_store::VcStore;

// ============================================================================
// Configuration
// ============================================================================

/// Adaptive polling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    /// Minimum poll interval in seconds
    pub min_interval_secs: u32,
    /// Maximum poll interval in seconds
    pub max_interval_secs: u32,
    /// Default poll interval in seconds
    pub default_interval_secs: u32,
    /// Number of consecutive failures before quarantine
    pub quarantine_after_failures: u32,
    /// Quarantine duration in seconds
    pub quarantine_duration_secs: u32,
    /// Backoff multiplier per failure (e.g. 2.0 for exponential)
    pub backoff_multiplier: f64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            min_interval_secs: 15,
            max_interval_secs: 300,
            default_interval_secs: 60,
            quarantine_after_failures: 5,
            quarantine_duration_secs: 600,
            backoff_multiplier: 2.0,
        }
    }
}

// ============================================================================
// Collector state tracking
// ============================================================================

/// Per-collector state for adaptive scheduling
#[derive(Debug, Clone)]
pub struct CollectorState {
    pub machine_id: String,
    pub collector: String,
    pub consecutive_failures: u32,
    pub last_interval_secs: u32,
    pub quarantined: bool,
    pub has_active_alert: bool,
    pub freshness_secs: Option<f64>,
}

impl CollectorState {
    pub fn new(machine_id: &str, collector: &str, default_interval: u32) -> Self {
        Self {
            machine_id: machine_id.to_string(),
            collector: collector.to_string(),
            consecutive_failures: 0,
            last_interval_secs: default_interval,
            quarantined: false,
            has_active_alert: false,
            freshness_secs: None,
        }
    }
}

// ============================================================================
// Schedule decision
// ============================================================================

/// A scheduling decision with rationale
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleDecision {
    pub machine_id: String,
    pub collector: String,
    pub interval_secs: u32,
    pub reason: ScheduleReason,
}

/// Why the interval was chosen
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleReason {
    /// Using default interval
    Default,
    /// Shortened due to active alerts
    AlertResponse,
    /// Shortened due to stale data
    FreshnessRecovery,
    /// Lengthened due to backoff after failures
    FailureBackoff,
    /// Collector quarantined - not polling
    Quarantined,
    /// On-demand profiling burst
    ProfilingBurst,
}

impl ScheduleReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Default => "default",
            Self::AlertResponse => "alert_response",
            Self::FreshnessRecovery => "freshness_recovery",
            Self::FailureBackoff => "failure_backoff",
            Self::Quarantined => "quarantined",
            Self::ProfilingBurst => "profiling_burst",
        }
    }
}

// ============================================================================
// Profiling burst
// ============================================================================

/// An on-demand profiling session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingSession {
    pub profile_id: String,
    pub machine_id: String,
    pub interval_secs: u32,
    pub duration_secs: u32,
    pub remaining_secs: u32,
}

// ============================================================================
// Adaptive scheduler
// ============================================================================

/// Adaptive poll scheduler
pub struct AdaptiveScheduler {
    config: AdaptiveConfig,
    states: HashMap<String, CollectorState>,
    profiling_sessions: HashMap<String, ProfilingSession>,
    store: Option<Arc<VcStore>>,
}

impl AdaptiveScheduler {
    /// Create a new scheduler with default config
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
            profiling_sessions: HashMap::new(),
            store: None,
        }
    }

    /// Create with store for decision logging
    pub fn with_store(config: AdaptiveConfig, store: Arc<VcStore>) -> Self {
        Self {
            config,
            states: HashMap::new(),
            profiling_sessions: HashMap::new(),
            store: Some(store),
        }
    }

    /// Get or create state for a collector
    fn get_state(&mut self, machine_id: &str, collector: &str) -> &mut CollectorState {
        let key = format!("{machine_id}:{collector}");
        self.states
            .entry(key)
            .or_insert_with(|| {
                CollectorState::new(machine_id, collector, self.config.default_interval_secs)
            })
    }

    /// Record a successful poll
    pub fn record_success(&mut self, machine_id: &str, collector: &str) {
        let state = self.get_state(machine_id, collector);
        state.consecutive_failures = 0;
        state.quarantined = false;
    }

    /// Record a failed poll
    pub fn record_failure(&mut self, machine_id: &str, collector: &str) {
        let threshold = self.config.quarantine_after_failures;
        let state = self.get_state(machine_id, collector);
        state.consecutive_failures += 1;
        if state.consecutive_failures >= threshold {
            state.quarantined = true;
        }
    }

    /// Set active alert status for a machine
    pub fn set_active_alert(&mut self, machine_id: &str, collector: &str, has_alert: bool) {
        let state = self.get_state(machine_id, collector);
        state.has_active_alert = has_alert;
    }

    /// Set freshness info
    pub fn set_freshness(&mut self, machine_id: &str, collector: &str, freshness_secs: f64) {
        let state = self.get_state(machine_id, collector);
        state.freshness_secs = Some(freshness_secs);
    }

    /// Reset quarantine for a collector
    pub fn reset_quarantine(&mut self, machine_id: &str, collector: &str) {
        let state = self.get_state(machine_id, collector);
        state.quarantined = false;
        state.consecutive_failures = 0;
    }

    /// Start a profiling session
    pub fn start_profiling(
        &mut self,
        profile_id: &str,
        machine_id: &str,
        interval_secs: u32,
        duration_secs: u32,
    ) {
        self.profiling_sessions.insert(
            machine_id.to_string(),
            ProfilingSession {
                profile_id: profile_id.to_string(),
                machine_id: machine_id.to_string(),
                interval_secs,
                duration_secs,
                remaining_secs: duration_secs,
            },
        );
    }

    /// Check if a machine has active profiling
    pub fn active_profiling(&self, machine_id: &str) -> Option<&ProfilingSession> {
        self.profiling_sessions
            .get(machine_id)
            .filter(|s| s.remaining_secs > 0)
    }

    /// Calculate the next poll interval for a collector
    pub fn compute_interval(&mut self, machine_id: &str, collector: &str) -> ScheduleDecision {
        // 1. Check profiling override
        if let Some(session) = self.profiling_sessions.get(machine_id) {
            if session.remaining_secs > 0 {
                let decision = ScheduleDecision {
                    machine_id: machine_id.to_string(),
                    collector: collector.to_string(),
                    interval_secs: session.interval_secs,
                    reason: ScheduleReason::ProfilingBurst,
                };
                self.log_decision(&decision);
                return decision;
            }
        }

        let key = format!("{machine_id}:{collector}");
        let state = self.states.get(&key);

        // 2. Check quarantine
        if let Some(state) = state {
            if state.quarantined {
                let decision = ScheduleDecision {
                    machine_id: machine_id.to_string(),
                    collector: collector.to_string(),
                    interval_secs: self.config.quarantine_duration_secs,
                    reason: ScheduleReason::Quarantined,
                };
                self.log_decision(&decision);
                return decision;
            }
        }

        // 3. Check failure backoff
        if let Some(state) = state {
            if state.consecutive_failures > 0 {
                let backoff = self.config.default_interval_secs as f64
                    * self.config.backoff_multiplier.powi(state.consecutive_failures as i32);
                let interval = (backoff as u32).min(self.config.max_interval_secs);
                let decision = ScheduleDecision {
                    machine_id: machine_id.to_string(),
                    collector: collector.to_string(),
                    interval_secs: interval,
                    reason: ScheduleReason::FailureBackoff,
                };
                self.log_decision(&decision);
                return decision;
            }
        }

        // 4. Check active alerts (shorter interval)
        if let Some(state) = state {
            if state.has_active_alert {
                let decision = ScheduleDecision {
                    machine_id: machine_id.to_string(),
                    collector: collector.to_string(),
                    interval_secs: self.config.min_interval_secs,
                    reason: ScheduleReason::AlertResponse,
                };
                self.log_decision(&decision);
                return decision;
            }
        }

        // 5. Check freshness (stale → poll sooner)
        if let Some(state) = state {
            if let Some(freshness) = state.freshness_secs {
                if freshness > (self.config.default_interval_secs * 3) as f64 {
                    let decision = ScheduleDecision {
                        machine_id: machine_id.to_string(),
                        collector: collector.to_string(),
                        interval_secs: self.config.min_interval_secs,
                        reason: ScheduleReason::FreshnessRecovery,
                    };
                    self.log_decision(&decision);
                    return decision;
                }
            }
        }

        // 6. Default interval
        let decision = ScheduleDecision {
            machine_id: machine_id.to_string(),
            collector: collector.to_string(),
            interval_secs: self.config.default_interval_secs,
            reason: ScheduleReason::Default,
        };
        self.log_decision(&decision);
        decision
    }

    /// Log a decision to the store
    fn log_decision(&self, decision: &ScheduleDecision) {
        if let Some(ref store) = self.store {
            let reason_json =
                serde_json::to_string(&serde_json::json!({"reason": decision.reason.as_str()}))
                    .unwrap_or_default();
            let _ = store.insert_poll_decision(
                &decision.machine_id,
                &decision.collector,
                decision.interval_secs as i32,
                Some(&reason_json),
            );
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> AdaptiveConfig {
        AdaptiveConfig {
            min_interval_secs: 10,
            max_interval_secs: 300,
            default_interval_secs: 60,
            quarantine_after_failures: 3,
            quarantine_duration_secs: 600,
            backoff_multiplier: 2.0,
        }
    }

    // ========================================================================
    // Config tests
    // ========================================================================

    #[test]
    fn test_default_config() {
        let config = AdaptiveConfig::default();
        assert_eq!(config.min_interval_secs, 15);
        assert_eq!(config.max_interval_secs, 300);
        assert_eq!(config.default_interval_secs, 60);
    }

    #[test]
    fn test_config_serialization() {
        let config = default_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AdaptiveConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.min_interval_secs, 10);
    }

    // ========================================================================
    // Default interval tests
    // ========================================================================

    #[test]
    fn test_default_interval() {
        let mut sched = AdaptiveScheduler::new(default_config());
        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.interval_secs, 60);
        assert_eq!(decision.reason, ScheduleReason::Default);
    }

    // ========================================================================
    // Failure backoff tests
    // ========================================================================

    #[test]
    fn test_single_failure_backoff() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.record_failure("orko", "sysmoni");

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::FailureBackoff);
        assert_eq!(decision.interval_secs, 120); // 60 * 2^1
    }

    #[test]
    fn test_multiple_failure_backoff() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.record_failure("orko", "sysmoni");
        sched.record_failure("orko", "sysmoni");

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.interval_secs, 240); // 60 * 2^2
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let mut config = default_config();
        config.quarantine_after_failures = 100; // high threshold so we stay in backoff
        let mut sched = AdaptiveScheduler::new(config);
        // Many failures should cap at max
        for _ in 0..10 {
            sched.record_failure("orko", "sysmoni");
        }

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::FailureBackoff);
        assert!(decision.interval_secs <= 300);
    }

    #[test]
    fn test_success_resets_backoff() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.record_failure("orko", "sysmoni");
        sched.record_failure("orko", "sysmoni");
        sched.record_success("orko", "sysmoni");

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::Default);
        assert_eq!(decision.interval_secs, 60);
    }

    // ========================================================================
    // Quarantine tests
    // ========================================================================

    #[test]
    fn test_quarantine_after_threshold() {
        let mut sched = AdaptiveScheduler::new(default_config());
        for _ in 0..3 {
            sched.record_failure("orko", "sysmoni");
        }

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::Quarantined);
        assert_eq!(decision.interval_secs, 600);
    }

    #[test]
    fn test_quarantine_reset() {
        let mut sched = AdaptiveScheduler::new(default_config());
        for _ in 0..3 {
            sched.record_failure("orko", "sysmoni");
        }

        sched.reset_quarantine("orko", "sysmoni");
        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::Default);
    }

    // ========================================================================
    // Alert response tests
    // ========================================================================

    #[test]
    fn test_alert_shortens_interval() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.set_active_alert("orko", "sysmoni", true);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::AlertResponse);
        assert_eq!(decision.interval_secs, 10); // min_interval
    }

    #[test]
    fn test_alert_cleared_restores_default() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.set_active_alert("orko", "sysmoni", true);
        sched.set_active_alert("orko", "sysmoni", false);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::Default);
    }

    // ========================================================================
    // Freshness recovery tests
    // ========================================================================

    #[test]
    fn test_stale_data_shortens_interval() {
        let mut sched = AdaptiveScheduler::new(default_config());
        // Freshness > 3x default (60*3 = 180)
        sched.set_freshness("orko", "sysmoni", 200.0);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::FreshnessRecovery);
        assert_eq!(decision.interval_secs, 10);
    }

    #[test]
    fn test_fresh_data_keeps_default() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.set_freshness("orko", "sysmoni", 30.0);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::Default);
    }

    // ========================================================================
    // Profiling burst tests
    // ========================================================================

    #[test]
    fn test_profiling_overrides_interval() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.start_profiling("prof-1", "orko", 2, 120);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::ProfilingBurst);
        assert_eq!(decision.interval_secs, 2);
    }

    #[test]
    fn test_profiling_active_check() {
        let mut sched = AdaptiveScheduler::new(default_config());
        assert!(sched.active_profiling("orko").is_none());

        sched.start_profiling("prof-1", "orko", 2, 120);
        assert!(sched.active_profiling("orko").is_some());
    }

    // ========================================================================
    // Priority ordering tests
    // ========================================================================

    #[test]
    fn test_profiling_beats_quarantine() {
        let mut sched = AdaptiveScheduler::new(default_config());
        for _ in 0..5 {
            sched.record_failure("orko", "sysmoni");
        }
        sched.start_profiling("prof-1", "orko", 2, 120);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::ProfilingBurst);
    }

    #[test]
    fn test_quarantine_beats_alert() {
        let mut sched = AdaptiveScheduler::new(default_config());
        for _ in 0..3 {
            sched.record_failure("orko", "sysmoni");
        }
        sched.set_active_alert("orko", "sysmoni", true);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::Quarantined);
    }

    #[test]
    fn test_backoff_beats_alert() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.record_failure("orko", "sysmoni");
        sched.set_active_alert("orko", "sysmoni", true);

        let decision = sched.compute_interval("orko", "sysmoni");
        assert_eq!(decision.reason, ScheduleReason::FailureBackoff);
    }

    // ========================================================================
    // Multi-collector tests
    // ========================================================================

    #[test]
    fn test_independent_collectors() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.record_failure("orko", "sysmoni");
        sched.set_active_alert("orko", "ntm", true);

        let sysmoni = sched.compute_interval("orko", "sysmoni");
        assert_eq!(sysmoni.reason, ScheduleReason::FailureBackoff);

        let ntm = sched.compute_interval("orko", "ntm");
        assert_eq!(ntm.reason, ScheduleReason::AlertResponse);
    }

    #[test]
    fn test_independent_machines() {
        let mut sched = AdaptiveScheduler::new(default_config());
        sched.set_active_alert("orko", "sysmoni", true);

        let orko = sched.compute_interval("orko", "sysmoni");
        assert_eq!(orko.reason, ScheduleReason::AlertResponse);

        let other = sched.compute_interval("other", "sysmoni");
        assert_eq!(other.reason, ScheduleReason::Default);
    }

    // ========================================================================
    // Store integration tests
    // ========================================================================

    #[test]
    fn test_decisions_logged_to_store() {
        let store = Arc::new(VcStore::open_memory().unwrap());
        let mut sched = AdaptiveScheduler::with_store(default_config(), store.clone());

        sched.compute_interval("orko", "sysmoni");

        let decisions = store.list_poll_decisions(Some("orko"), 10).unwrap();
        assert_eq!(decisions.len(), 1);
    }

    // ========================================================================
    // Serialization tests
    // ========================================================================

    #[test]
    fn test_schedule_decision_serialization() {
        let decision = ScheduleDecision {
            machine_id: "orko".to_string(),
            collector: "sysmoni".to_string(),
            interval_secs: 60,
            reason: ScheduleReason::Default,
        };

        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ScheduleDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.interval_secs, 60);
        assert_eq!(parsed.reason, ScheduleReason::Default);
    }

    #[test]
    fn test_profiling_session_serialization() {
        let session = ProfilingSession {
            profile_id: "p-1".to_string(),
            machine_id: "orko".to_string(),
            interval_secs: 2,
            duration_secs: 120,
            remaining_secs: 100,
        };

        let json = serde_json::to_string(&session).unwrap();
        let parsed: ProfilingSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.profile_id, "p-1");
    }
}
