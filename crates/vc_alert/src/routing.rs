//! Alert routing, escalation, and suppression engine
//!
//! Routes alerts to channels based on configurable rules:
//! - Severity-based routing
//! - Machine/tag pattern matching
//! - Quiet hours / suppression windows
//! - Escalation after SLA timeout
//! - Dedup/throttle per rule

use crate::Severity;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vc_store::VcStore;

// ============================================================================
// Routing rule types
// ============================================================================

/// A routing rule that determines where an alert should be delivered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Unique rule identifier
    pub rule_id: String,
    /// Human-readable name
    pub name: String,
    /// Match condition for this rule
    pub match_condition: MatchCondition,
    /// Channels to deliver to when matched
    pub channels: Vec<String>,
    /// Whether to suppress (not deliver) matching alerts
    pub suppress: bool,
    /// Priority (lower = higher priority, evaluated first)
    pub priority: u32,
    /// Whether rule is enabled
    pub enabled: bool,
}

/// Condition for matching alerts to routing rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    /// Match by severity (None = match all)
    pub severity: Option<Vec<Severity>>,
    /// Match by machine name pattern (glob-like)
    pub machine_pattern: Option<String>,
    /// Match by alert rule ID pattern
    pub alert_rule_pattern: Option<String>,
}

impl MatchCondition {
    /// Check if this condition matches a given alert context
    #[must_use]
    pub fn matches(&self, alert: &AlertContext) -> bool {
        // Severity check
        if let Some(ref severities) = self.severity
            && !severities.contains(&alert.severity)
        {
            return false;
        }

        // Machine pattern check (simple contains/glob matching)
        if let Some(ref pattern) = self.machine_pattern {
            if let Some(ref machine) = alert.machine_id {
                if !simple_match(pattern, machine) {
                    return false;
                }
            } else {
                return false; // Pattern requires a machine
            }
        }

        // Alert rule pattern check
        if let Some(ref pattern) = self.alert_rule_pattern
            && !simple_match(pattern, &alert.alert_rule_id)
        {
            return false;
        }

        true
    }
}

/// Context about an alert being routed
#[derive(Debug, Clone)]
pub struct AlertContext {
    pub alert_id: String,
    pub alert_rule_id: String,
    pub severity: Severity,
    pub machine_id: Option<String>,
    pub fired_at: String,
}

// ============================================================================
// Quiet hours / suppression window
// ============================================================================

/// A quiet hours window during which low-severity alerts are suppressed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    /// Start hour (0-23)
    pub start_hour: u8,
    /// End hour (0-23)
    pub end_hour: u8,
    /// Severity threshold: alerts below this severity are suppressed during quiet hours
    pub suppress_below: Severity,
    /// Whether quiet hours are enabled
    pub enabled: bool,
}

impl QuietHours {
    /// Check if an alert should be suppressed given the current hour
    #[must_use]
    pub fn should_suppress(&self, current_hour: u8, severity: Severity) -> bool {
        if !self.enabled {
            return false;
        }
        if severity >= self.suppress_below {
            return false; // Never suppress critical alerts
        }

        // Handle wrapping (e.g. 22:00 - 06:00)
        if self.start_hour <= self.end_hour {
            current_hour >= self.start_hour && current_hour < self.end_hour
        } else {
            current_hour >= self.start_hour || current_hour < self.end_hour
        }
    }
}

// ============================================================================
// Escalation policy
// ============================================================================

/// Escalation policy for unacknowledged alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Policy identifier
    pub policy_id: String,
    /// Severity threshold for escalation
    pub min_severity: Severity,
    /// Minutes before escalation
    pub escalate_after_mins: u64,
    /// Channels to escalate to
    pub escalate_to: Vec<String>,
    /// Whether policy is enabled
    pub enabled: bool,
}

// ============================================================================
// Routing decision
// ============================================================================

/// The result of routing an alert through rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Alert ID
    pub alert_id: String,
    /// Matched rule ID (if any)
    pub matched_rule: Option<String>,
    /// Action taken
    pub action: RoutingAction,
    /// Channels to deliver to
    pub channels: Vec<String>,
    /// Reason for the decision
    pub reason: String,
}

/// Actions taken by the routing engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingAction {
    /// Alert sent to channels
    Sent,
    /// Alert suppressed (quiet hours or rule)
    Suppressed,
    /// Alert escalated after timeout
    Escalated,
    /// No matching rule found, using defaults
    DefaultRoute,
}

impl RoutingAction {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sent => "sent",
            Self::Suppressed => "suppressed",
            Self::Escalated => "escalated",
            Self::DefaultRoute => "default_route",
        }
    }
}

// ============================================================================
// Routing engine
// ============================================================================

/// Alert routing engine
pub struct RoutingEngine {
    rules: Vec<RoutingRule>,
    quiet_hours: Option<QuietHours>,
    escalation_policies: Vec<EscalationPolicy>,
    default_channels: Vec<String>,
    store: Option<Arc<VcStore>>,
}

impl RoutingEngine {
    /// Create a new routing engine with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            quiet_hours: None,
            escalation_policies: Vec::new(),
            default_channels: vec!["log".to_string()],
            store: None,
        }
    }

    /// Create with a store for audit logging
    #[must_use]
    pub fn with_store(store: Arc<VcStore>) -> Self {
        Self {
            rules: Vec::new(),
            quiet_hours: None,
            escalation_policies: Vec::new(),
            default_channels: vec!["log".to_string()],
            store: Some(store),
        }
    }

    /// Add a routing rule
    pub fn add_rule(&mut self, rule: RoutingRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Set quiet hours
    pub fn set_quiet_hours(&mut self, quiet_hours: QuietHours) {
        self.quiet_hours = Some(quiet_hours);
    }

    /// Add an escalation policy
    pub fn add_escalation_policy(&mut self, policy: EscalationPolicy) {
        self.escalation_policies.push(policy);
    }

    /// Set default channels for unmatched alerts
    pub fn set_default_channels(&mut self, channels: Vec<String>) {
        self.default_channels = channels;
    }

    /// Route an alert through the rules engine
    #[must_use]
    pub fn route(&self, alert: &AlertContext, current_hour: u8) -> RoutingDecision {
        // 1. Check quiet hours suppression
        if let Some(ref qh) = self.quiet_hours
            && qh.should_suppress(current_hour, alert.severity)
        {
            let decision = RoutingDecision {
                alert_id: alert.alert_id.clone(),
                matched_rule: None,
                action: RoutingAction::Suppressed,
                channels: vec![],
                reason: format!(
                    "Suppressed during quiet hours ({:02}:00-{:02}:00)",
                    qh.start_hour, qh.end_hour
                ),
            };
            self.audit_decision(&decision);
            return decision;
        }

        // 2. Check routing rules in priority order
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if rule.match_condition.matches(alert) {
                if rule.suppress {
                    let decision = RoutingDecision {
                        alert_id: alert.alert_id.clone(),
                        matched_rule: Some(rule.rule_id.clone()),
                        action: RoutingAction::Suppressed,
                        channels: vec![],
                        reason: format!("Suppressed by rule: {}", rule.name),
                    };
                    self.audit_decision(&decision);
                    return decision;
                }

                let decision = RoutingDecision {
                    alert_id: alert.alert_id.clone(),
                    matched_rule: Some(rule.rule_id.clone()),
                    action: RoutingAction::Sent,
                    channels: rule.channels.clone(),
                    reason: format!("Matched rule: {}", rule.name),
                };
                self.audit_decision(&decision);
                return decision;
            }
        }

        // 3. Default route
        let decision = RoutingDecision {
            alert_id: alert.alert_id.clone(),
            matched_rule: None,
            action: RoutingAction::DefaultRoute,
            channels: self.default_channels.clone(),
            reason: "No matching rule, using defaults".to_string(),
        };
        self.audit_decision(&decision);
        decision
    }

    /// Check for alerts that should be escalated
    #[must_use]
    pub fn check_escalation(
        &self,
        alert: &AlertContext,
        minutes_unacked: u64,
    ) -> Option<RoutingDecision> {
        for policy in &self.escalation_policies {
            if !policy.enabled {
                continue;
            }
            if alert.severity >= policy.min_severity
                && minutes_unacked >= policy.escalate_after_mins
            {
                let decision = RoutingDecision {
                    alert_id: alert.alert_id.clone(),
                    matched_rule: Some(policy.policy_id.clone()),
                    action: RoutingAction::Escalated,
                    channels: policy.escalate_to.clone(),
                    reason: format!(
                        "Escalated after {} minutes (policy: {})",
                        minutes_unacked, policy.policy_id
                    ),
                };
                self.audit_decision(&decision);
                return Some(decision);
            }
        }
        None
    }

    /// Record a routing decision in the audit log
    fn audit_decision(&self, decision: &RoutingDecision) {
        if let Some(ref store) = self.store {
            let reason_json =
                serde_json::to_string(&serde_json::json!({"reason": &decision.reason}))
                    .unwrap_or_default();
            let channel = decision.channels.join(",");
            let _ = store.insert_routing_event(
                &decision.alert_id,
                decision.matched_rule.as_deref(),
                &channel,
                decision.action.as_str(),
                Some(&reason_json),
            );
        }
    }
}

impl Default for RoutingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Simple pattern matching: supports `*` wildcard at start/end
fn simple_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alert(severity: Severity) -> AlertContext {
        AlertContext {
            alert_id: "alert-1".to_string(),
            alert_rule_id: "rule-cpu-high".to_string(),
            severity,
            machine_id: Some("orko".to_string()),
            fired_at: "2026-02-20T10:00:00".to_string(),
        }
    }

    fn critical_rule() -> RoutingRule {
        RoutingRule {
            rule_id: "r-crit".to_string(),
            name: "Critical alerts to Slack".to_string(),
            match_condition: MatchCondition {
                severity: Some(vec![Severity::Critical]),
                machine_pattern: None,
                alert_rule_pattern: None,
            },
            channels: vec!["slack".to_string(), "desktop".to_string()],
            suppress: false,
            priority: 1,
            enabled: true,
        }
    }

    fn warning_rule() -> RoutingRule {
        RoutingRule {
            rule_id: "r-warn".to_string(),
            name: "Warnings to log".to_string(),
            match_condition: MatchCondition {
                severity: Some(vec![Severity::Warning]),
                machine_pattern: None,
                alert_rule_pattern: None,
            },
            channels: vec!["log".to_string()],
            suppress: false,
            priority: 2,
            enabled: true,
        }
    }

    // ========================================================================
    // MatchCondition tests
    // ========================================================================

    #[test]
    fn test_match_all() {
        let cond = MatchCondition {
            severity: None,
            machine_pattern: None,
            alert_rule_pattern: None,
        };
        assert!(cond.matches(&test_alert(Severity::Info)));
        assert!(cond.matches(&test_alert(Severity::Critical)));
    }

    #[test]
    fn test_match_severity() {
        let cond = MatchCondition {
            severity: Some(vec![Severity::Critical]),
            machine_pattern: None,
            alert_rule_pattern: None,
        };
        assert!(cond.matches(&test_alert(Severity::Critical)));
        assert!(!cond.matches(&test_alert(Severity::Warning)));
        assert!(!cond.matches(&test_alert(Severity::Info)));
    }

    #[test]
    fn test_match_machine_exact() {
        let cond = MatchCondition {
            severity: None,
            machine_pattern: Some("orko".to_string()),
            alert_rule_pattern: None,
        };
        assert!(cond.matches(&test_alert(Severity::Info)));

        let mut alert = test_alert(Severity::Info);
        alert.machine_id = Some("other".to_string());
        assert!(!cond.matches(&alert));
    }

    #[test]
    fn test_match_machine_wildcard_suffix() {
        let cond = MatchCondition {
            severity: None,
            machine_pattern: Some("ork*".to_string()),
            alert_rule_pattern: None,
        };
        assert!(cond.matches(&test_alert(Severity::Info)));

        let mut alert = test_alert(Severity::Info);
        alert.machine_id = Some("other".to_string());
        assert!(!cond.matches(&alert));
    }

    #[test]
    fn test_match_machine_wildcard_prefix() {
        let cond = MatchCondition {
            severity: None,
            machine_pattern: Some("*rko".to_string()),
            alert_rule_pattern: None,
        };
        assert!(cond.matches(&test_alert(Severity::Info)));
    }

    #[test]
    fn test_match_no_machine_with_pattern() {
        let cond = MatchCondition {
            severity: None,
            machine_pattern: Some("orko".to_string()),
            alert_rule_pattern: None,
        };
        let mut alert = test_alert(Severity::Info);
        alert.machine_id = None;
        assert!(!cond.matches(&alert)); // Pattern requires machine
    }

    #[test]
    fn test_match_alert_rule_pattern() {
        let cond = MatchCondition {
            severity: None,
            machine_pattern: None,
            alert_rule_pattern: Some("rule-cpu*".to_string()),
        };
        assert!(cond.matches(&test_alert(Severity::Info)));

        let mut alert = test_alert(Severity::Info);
        alert.alert_rule_id = "rule-memory".to_string();
        assert!(!cond.matches(&alert));
    }

    #[test]
    fn test_match_combined() {
        let cond = MatchCondition {
            severity: Some(vec![Severity::Critical]),
            machine_pattern: Some("orko".to_string()),
            alert_rule_pattern: None,
        };
        assert!(cond.matches(&test_alert(Severity::Critical)));
        assert!(!cond.matches(&test_alert(Severity::Warning))); // Wrong severity
    }

    // ========================================================================
    // Quiet hours tests
    // ========================================================================

    #[test]
    fn test_quiet_hours_in_window() {
        let qh = QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: true,
        };
        assert!(qh.should_suppress(23, Severity::Info));
        assert!(qh.should_suppress(0, Severity::Info));
        assert!(qh.should_suppress(5, Severity::Warning));
    }

    #[test]
    fn test_quiet_hours_outside_window() {
        let qh = QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: true,
        };
        assert!(!qh.should_suppress(12, Severity::Info));
        assert!(!qh.should_suppress(21, Severity::Info));
        assert!(!qh.should_suppress(6, Severity::Info));
    }

    #[test]
    fn test_quiet_hours_critical_never_suppressed() {
        let qh = QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: true,
        };
        assert!(!qh.should_suppress(23, Severity::Critical));
    }

    #[test]
    fn test_quiet_hours_disabled() {
        let qh = QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: false,
        };
        assert!(!qh.should_suppress(23, Severity::Info));
    }

    #[test]
    fn test_quiet_hours_same_day() {
        let qh = QuietHours {
            start_hour: 9,
            end_hour: 17,
            suppress_below: Severity::Warning,
            enabled: true,
        };
        assert!(qh.should_suppress(12, Severity::Info));
        assert!(!qh.should_suppress(18, Severity::Info));
        assert!(!qh.should_suppress(12, Severity::Warning)); // At threshold
    }

    // ========================================================================
    // Routing engine tests
    // ========================================================================

    #[test]
    fn test_route_no_rules_default() {
        let engine = RoutingEngine::new();
        let alert = test_alert(Severity::Warning);
        let decision = engine.route(&alert, 12);

        assert_eq!(decision.action, RoutingAction::DefaultRoute);
        assert_eq!(decision.channels, vec!["log"]);
    }

    #[test]
    fn test_route_matching_rule() {
        let mut engine = RoutingEngine::new();
        engine.add_rule(critical_rule());
        engine.add_rule(warning_rule());

        let decision = engine.route(&test_alert(Severity::Critical), 12);
        assert_eq!(decision.action, RoutingAction::Sent);
        assert_eq!(decision.matched_rule, Some("r-crit".to_string()));
        assert!(decision.channels.contains(&"slack".to_string()));
    }

    #[test]
    fn test_route_warning_matches_warning_rule() {
        let mut engine = RoutingEngine::new();
        engine.add_rule(critical_rule());
        engine.add_rule(warning_rule());

        let decision = engine.route(&test_alert(Severity::Warning), 12);
        assert_eq!(decision.action, RoutingAction::Sent);
        assert_eq!(decision.matched_rule, Some("r-warn".to_string()));
        assert_eq!(decision.channels, vec!["log"]);
    }

    #[test]
    fn test_route_info_falls_to_default() {
        let mut engine = RoutingEngine::new();
        engine.add_rule(critical_rule());
        engine.add_rule(warning_rule());

        let decision = engine.route(&test_alert(Severity::Info), 12);
        assert_eq!(decision.action, RoutingAction::DefaultRoute);
    }

    #[test]
    fn test_route_suppression_rule() {
        let mut engine = RoutingEngine::new();
        engine.add_rule(RoutingRule {
            rule_id: "r-suppress".to_string(),
            name: "Suppress info alerts".to_string(),
            match_condition: MatchCondition {
                severity: Some(vec![Severity::Info]),
                machine_pattern: None,
                alert_rule_pattern: None,
            },
            channels: vec![],
            suppress: true,
            priority: 0,
            enabled: true,
        });

        let decision = engine.route(&test_alert(Severity::Info), 12);
        assert_eq!(decision.action, RoutingAction::Suppressed);
        assert!(decision.channels.is_empty());
    }

    #[test]
    fn test_route_quiet_hours_suppression() {
        let mut engine = RoutingEngine::new();
        engine.set_quiet_hours(QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: true,
        });

        // Info alert during quiet hours
        let decision = engine.route(&test_alert(Severity::Info), 23);
        assert_eq!(decision.action, RoutingAction::Suppressed);

        // Critical alert during quiet hours - NOT suppressed
        let decision = engine.route(&test_alert(Severity::Critical), 23);
        assert_ne!(decision.action, RoutingAction::Suppressed);
    }

    #[test]
    fn test_route_disabled_rule_skipped() {
        let mut engine = RoutingEngine::new();
        let mut rule = critical_rule();
        rule.enabled = false;
        engine.add_rule(rule);

        let decision = engine.route(&test_alert(Severity::Critical), 12);
        assert_eq!(decision.action, RoutingAction::DefaultRoute);
    }

    #[test]
    fn test_route_priority_ordering() {
        let mut engine = RoutingEngine::new();

        // Lower priority number = higher priority
        engine.add_rule(RoutingRule {
            rule_id: "r-low-pri".to_string(),
            name: "Low priority".to_string(),
            match_condition: MatchCondition {
                severity: Some(vec![Severity::Critical]),
                machine_pattern: None,
                alert_rule_pattern: None,
            },
            channels: vec!["email".to_string()],
            suppress: false,
            priority: 10,
            enabled: true,
        });
        engine.add_rule(RoutingRule {
            rule_id: "r-high-pri".to_string(),
            name: "High priority".to_string(),
            match_condition: MatchCondition {
                severity: Some(vec![Severity::Critical]),
                machine_pattern: None,
                alert_rule_pattern: None,
            },
            channels: vec!["slack".to_string()],
            suppress: false,
            priority: 1,
            enabled: true,
        });

        let decision = engine.route(&test_alert(Severity::Critical), 12);
        assert_eq!(decision.matched_rule, Some("r-high-pri".to_string()));
        assert_eq!(decision.channels, vec!["slack"]);
    }

    // ========================================================================
    // Escalation tests
    // ========================================================================

    #[test]
    fn test_escalation_triggered() {
        let mut engine = RoutingEngine::new();
        engine.add_escalation_policy(EscalationPolicy {
            policy_id: "esc-1".to_string(),
            min_severity: Severity::Warning,
            escalate_after_mins: 15,
            escalate_to: vec!["slack".to_string(), "pagerduty".to_string()],
            enabled: true,
        });

        let result = engine.check_escalation(&test_alert(Severity::Critical), 20);
        assert!(result.is_some());
        let decision = result.unwrap();
        assert_eq!(decision.action, RoutingAction::Escalated);
        assert!(decision.channels.contains(&"pagerduty".to_string()));
    }

    #[test]
    fn test_escalation_not_yet() {
        let mut engine = RoutingEngine::new();
        engine.add_escalation_policy(EscalationPolicy {
            policy_id: "esc-1".to_string(),
            min_severity: Severity::Warning,
            escalate_after_mins: 15,
            escalate_to: vec!["slack".to_string()],
            enabled: true,
        });

        let result = engine.check_escalation(&test_alert(Severity::Critical), 10);
        assert!(result.is_none());
    }

    #[test]
    fn test_escalation_below_severity() {
        let mut engine = RoutingEngine::new();
        engine.add_escalation_policy(EscalationPolicy {
            policy_id: "esc-1".to_string(),
            min_severity: Severity::Critical,
            escalate_after_mins: 5,
            escalate_to: vec!["slack".to_string()],
            enabled: true,
        });

        let result = engine.check_escalation(&test_alert(Severity::Info), 60);
        assert!(result.is_none()); // Info < Critical
    }

    #[test]
    fn test_escalation_disabled() {
        let mut engine = RoutingEngine::new();
        engine.add_escalation_policy(EscalationPolicy {
            policy_id: "esc-1".to_string(),
            min_severity: Severity::Info,
            escalate_after_mins: 1,
            escalate_to: vec!["slack".to_string()],
            enabled: false,
        });

        let result = engine.check_escalation(&test_alert(Severity::Critical), 60);
        assert!(result.is_none());
    }

    // ========================================================================
    // Store integration tests
    // ========================================================================

    #[test]
    fn test_routing_with_store_audit() {
        let store = Arc::new(VcStore::open_memory().unwrap());
        let mut engine = RoutingEngine::with_store(store.clone());
        engine.add_rule(critical_rule());

        let alert = test_alert(Severity::Critical);
        let _decision = engine.route(&alert, 12);

        // Check that the routing event was recorded
        let events = store.list_routing_events(Some("alert-1"), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"].as_str(), Some("sent"));
    }

    #[test]
    fn test_routing_suppression_audited() {
        let store = Arc::new(VcStore::open_memory().unwrap());
        let mut engine = RoutingEngine::with_store(store.clone());
        engine.set_quiet_hours(QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: true,
        });

        let _decision = engine.route(&test_alert(Severity::Info), 23);

        let events = store.list_routing_events(Some("alert-1"), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"].as_str(), Some("suppressed"));
    }

    // ========================================================================
    // Serialization tests
    // ========================================================================

    #[test]
    fn test_routing_rule_serialization() {
        let rule = critical_rule();
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: RoutingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rule_id, "r-crit");
        assert_eq!(parsed.channels, vec!["slack", "desktop"]);
    }

    #[test]
    fn test_routing_decision_serialization() {
        let decision = RoutingDecision {
            alert_id: "a-1".to_string(),
            matched_rule: Some("r-1".to_string()),
            action: RoutingAction::Sent,
            channels: vec!["slack".to_string()],
            reason: "test".to_string(),
        };

        let json = serde_json::to_string(&decision).unwrap();
        let parsed: RoutingDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, RoutingAction::Sent);
    }

    #[test]
    fn test_quiet_hours_serialization() {
        let qh = QuietHours {
            start_hour: 22,
            end_hour: 6,
            suppress_below: Severity::Critical,
            enabled: true,
        };

        let json = serde_json::to_string(&qh).unwrap();
        let parsed: QuietHours = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.start_hour, 22);
    }

    // ========================================================================
    // Simple match helper tests
    // ========================================================================

    #[test]
    fn test_simple_match_exact() {
        assert!(simple_match("orko", "orko"));
        assert!(!simple_match("orko", "other"));
    }

    #[test]
    fn test_simple_match_wildcard_all() {
        assert!(simple_match("*", "anything"));
        assert!(simple_match("*", ""));
    }

    #[test]
    fn test_simple_match_wildcard_prefix() {
        assert!(simple_match("*rko", "orko"));
        assert!(!simple_match("*rko", "other"));
    }

    #[test]
    fn test_simple_match_wildcard_suffix() {
        assert!(simple_match("ork*", "orko"));
        assert!(simple_match("ork*", "orkney"));
        assert!(!simple_match("ork*", "other"));
    }
}
