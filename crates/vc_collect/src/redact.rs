//! Secrets/PII redaction pipeline
//!
//! Scans collected data for sensitive patterns (API keys, tokens, passwords,
//! emails, SSNs, etc.) and replaces them with redaction markers.
//!
//! Supports per-collector rule overrides and tracks redaction stats.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use vc_store::VcStore;

// ============================================================================
// Redaction rules
// ============================================================================

/// A redaction rule with a regex pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRule {
    /// Rule identifier
    pub name: String,
    /// Regex pattern to match
    pub pattern: String,
    /// Replacement text (default: "[REDACTED]")
    pub replacement: String,
    /// Description of what this rule catches
    pub description: String,
}

/// Built-in redaction rules for common secret patterns
#[must_use]
pub fn default_rules() -> Vec<RedactionRule> {
    // Order matters: specific patterns before generic ones
    vec![
        RedactionRule {
            name: "aws_key".to_string(),
            pattern: r"(?i)(AKIA[0-9A-Z]{16})".to_string(),
            replacement: "[REDACTED:aws_key]".to_string(),
            description: "AWS Access Key ID".to_string(),
        },
        RedactionRule {
            name: "github_token".to_string(),
            pattern: r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}".to_string(),
            replacement: "[REDACTED:github_token]".to_string(),
            description: "GitHub personal access token".to_string(),
        },
        RedactionRule {
            name: "bearer_token".to_string(),
            pattern: r"(?i)Bearer\s+[A-Za-z0-9\-_\.]{20,}".to_string(),
            replacement: "[REDACTED:bearer]".to_string(),
            description: "Bearer token in Authorization header".to_string(),
        },
        RedactionRule {
            name: "private_key".to_string(),
            pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".to_string(),
            replacement: "[REDACTED:private_key]".to_string(),
            description: "Private key header".to_string(),
        },
        RedactionRule {
            name: "ssh_key_content".to_string(),
            pattern: r"ssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{40,}".to_string(),
            replacement: "[REDACTED:ssh_key]".to_string(),
            description: "SSH public key content".to_string(),
        },
        RedactionRule {
            name: "generic_secret".to_string(),
            pattern: r#"(?i)(?:password|passwd|secret|api_key|apikey|api-key)\s*[=:]\s*["']?([^\s"',}{]{8,})"#.to_string(),
            replacement: "[REDACTED:secret]".to_string(),
            description: "Generic secret pattern (key=value)".to_string(),
        },
        RedactionRule {
            name: "email".to_string(),
            pattern: r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}".to_string(),
            replacement: "[REDACTED:email]".to_string(),
            description: "Email address".to_string(),
        },
        RedactionRule {
            name: "ipv4".to_string(),
            pattern: r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b".to_string(),
            replacement: "[REDACTED:internal_ip]".to_string(),
            description: "Internal/private IPv4 address".to_string(),
        },
    ]
}

// ============================================================================
// Compiled rule set
// ============================================================================

/// A compiled redaction rule with a regex ready for matching
struct CompiledRule {
    name: String,
    regex: Regex,
    replacement: String,
}

// ============================================================================
// Redaction stats
// ============================================================================

/// Statistics from a redaction pass
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedactionStats {
    /// Number of fields that had redactions applied
    pub fields_redacted: usize,
    /// Total bytes redacted (original minus replacement)
    pub bytes_redacted: usize,
    /// Per-rule match counts
    pub rule_matches: Vec<(String, usize)>,
}

// ============================================================================
// Redaction engine
// ============================================================================

/// The redaction engine applies rules to text and JSON
pub struct RedactionEngine {
    rules: Vec<CompiledRule>,
    /// Version string for tracking rule changes
    pub rules_version: String,
    /// Fields to skip redaction on (allowlist)
    allowlist: Vec<String>,
    /// Optional store for logging
    store: Option<Arc<VcStore>>,
}

impl Default for RedactionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionEngine {
    /// Create with default rules
    #[must_use]
    pub fn new() -> Self {
        Self::with_rules(default_rules(), "v1")
    }

    /// Create with custom rules
    #[must_use]
    pub fn with_rules(rules: Vec<RedactionRule>, version: &str) -> Self {
        let compiled = rules
            .into_iter()
            .filter_map(|r| {
                Regex::new(&r.pattern).ok().map(|regex| CompiledRule {
                    name: r.name,
                    regex,
                    replacement: r.replacement,
                })
            })
            .collect();

        Self {
            rules: compiled,
            rules_version: version.to_string(),
            allowlist: vec![
                "machine_id".to_string(),
                "collector".to_string(),
                "collected_at".to_string(),
                "schema_version".to_string(),
            ],
            store: None,
        }
    }

    /// Attach a store for logging redaction events
    #[must_use]
    pub fn with_store(mut self, store: Arc<VcStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Add fields to the allowlist (skip redaction)
    pub fn add_allowlist(&mut self, fields: &[&str]) {
        for f in fields {
            self.allowlist.push(f.to_string());
        }
    }

    /// Redact a string, returning the redacted text and stats
    #[must_use]
    pub fn redact_text(&self, input: &str) -> (String, RedactionStats) {
        let mut output = input.to_string();
        let mut stats = RedactionStats::default();

        for rule in &self.rules {
            let count = rule.regex.find_iter(&output).count();
            if count > 0 {
                let before_len = output.len();
                output = rule
                    .regex
                    .replace_all(&output, &*rule.replacement)
                    .to_string();
                let after_len = output.len();

                stats.fields_redacted += count;
                if before_len > after_len {
                    stats.bytes_redacted += before_len - after_len;
                }
                stats.rule_matches.push((rule.name.clone(), count));
            }
        }

        (output, stats)
    }

    /// Redact a JSON value in-place, respecting the allowlist
    pub fn redact_json(&self, value: &mut serde_json::Value) -> RedactionStats {
        let mut stats = RedactionStats::default();
        self.redact_value(value, &mut stats, None);
        stats
    }

    fn redact_value(
        &self,
        value: &mut serde_json::Value,
        stats: &mut RedactionStats,
        field_name: Option<&str>,
    ) {
        // Skip allowlisted fields
        if let Some(name) = field_name
            && self.allowlist.iter().any(|a| a == name)
        {
            return;
        }

        match value {
            serde_json::Value::String(s) => {
                let (redacted, local_stats) = self.redact_text(s);
                if local_stats.fields_redacted > 0 {
                    *s = redacted;
                    stats.fields_redacted += local_stats.fields_redacted;
                    stats.bytes_redacted += local_stats.bytes_redacted;
                    stats.rule_matches.extend(local_stats.rule_matches);
                }
            }
            serde_json::Value::Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for key in keys {
                    if let Some(v) = map.get_mut(&key) {
                        self.redact_value(v, stats, Some(&key));
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_value(item, stats, None);
                }
            }
            _ => {}
        }
    }

    /// Redact and log to store
    pub fn redact_and_log(
        &self,
        machine_id: &str,
        collector: &str,
        value: &mut serde_json::Value,
    ) -> RedactionStats {
        let stats = self.redact_json(value);

        if stats.fields_redacted > 0
            && let Some(ref store) = self.store
        {
            let hash = content_hash(&serde_json::to_string(value).unwrap_or_default());
            let fields_redacted = i32::try_from(stats.fields_redacted).unwrap_or(i32::MAX);
            let bytes_redacted = i64::try_from(stats.bytes_redacted).unwrap_or(i64::MAX);
            let _ = store.insert_redaction_event(
                machine_id,
                collector,
                fields_redacted,
                bytes_redacted,
                &self.rules_version,
                Some(&hash),
            );
        }

        stats
    }

    /// Get the number of compiled rules
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn content_hash(s: &str) -> String {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> RedactionEngine {
        RedactionEngine::new()
    }

    // ========================================================================
    // Default rules tests
    // ========================================================================

    #[test]
    fn test_default_rules_count() {
        let rules = default_rules();
        assert!(rules.len() >= 7);
    }

    #[test]
    fn test_default_rules_compile() {
        let engine = engine();
        assert_eq!(engine.rule_count(), default_rules().len());
    }

    // ========================================================================
    // AWS key detection
    // ========================================================================

    #[test]
    fn test_redact_aws_key() {
        let engine = engine();
        let input = "key=AKIAIOSFODNN7EXAMPLE";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:aws_key]"));
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(stats.fields_redacted > 0);
    }

    // ========================================================================
    // Generic secret detection
    // ========================================================================

    #[test]
    fn test_redact_password_value() {
        let engine = engine();
        let input = r#"password = "super_secret_123""#;
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:secret]"));
        assert!(!output.contains("super_secret_123"));
        assert!(stats.fields_redacted > 0);
    }

    #[test]
    fn test_redact_api_key_value() {
        let engine = engine();
        let input = "api_key=abcdef1234567890";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:secret]"));
        assert!(stats.fields_redacted > 0);
    }

    // ========================================================================
    // Bearer token detection
    // ========================================================================

    #[test]
    fn test_redact_bearer_token() {
        let engine = engine();
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:bearer]"));
        assert!(stats.fields_redacted > 0);
    }

    // ========================================================================
    // Private key detection
    // ========================================================================

    #[test]
    fn test_redact_private_key() {
        let engine = engine();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:private_key]"));
        assert!(stats.fields_redacted > 0);
    }

    // ========================================================================
    // Email detection
    // ========================================================================

    #[test]
    fn test_redact_email() {
        let engine = engine();
        let input = "contact: alice@example.com";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:email]"));
        assert!(!output.contains("alice@example.com"));
        assert!(stats.fields_redacted > 0);
    }

    // ========================================================================
    // Internal IP detection
    // ========================================================================

    #[test]
    fn test_redact_internal_ip() {
        let engine = engine();
        let input = "server at 192.168.1.100";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:internal_ip]"));
        assert!(stats.fields_redacted > 0);
    }

    #[test]
    fn test_no_redact_public_ip() {
        let engine = engine();
        let input = "server at 8.8.8.8";
        let (output, stats) = engine.redact_text(input);
        assert_eq!(output, input);
        assert_eq!(stats.fields_redacted, 0);
    }

    // ========================================================================
    // GitHub token detection
    // ========================================================================

    #[test]
    fn test_redact_github_token() {
        let engine = engine();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let (output, stats) = engine.redact_text(input);
        assert!(output.contains("[REDACTED:github_token]"));
        assert!(stats.fields_redacted > 0);
    }

    // ========================================================================
    // No false positives on clean text
    // ========================================================================

    #[test]
    fn test_no_redaction_clean() {
        let engine = engine();
        let input = "cpu_pct: 42.5, mem_pct: 67.2";
        let (output, stats) = engine.redact_text(input);
        assert_eq!(output, input);
        assert_eq!(stats.fields_redacted, 0);
    }

    // ========================================================================
    // JSON redaction tests
    // ========================================================================

    #[test]
    fn test_redact_json_simple() {
        let engine = engine();
        let mut json = serde_json::json!({
            "cpu": 42.0,
            "notes": "password=hunter2secret"
        });
        let stats = engine.redact_json(&mut json);
        assert!(stats.fields_redacted > 0);
        let notes = json["notes"].as_str().unwrap();
        assert!(notes.contains("[REDACTED"));
    }

    #[test]
    fn test_redact_json_nested() {
        let engine = engine();
        let mut json = serde_json::json!({
            "data": {
                "config": {
                    "api_key": "secret=very_long_secret_value_here"
                }
            }
        });
        let stats = engine.redact_json(&mut json);
        assert!(stats.fields_redacted > 0);
    }

    #[test]
    fn test_redact_json_array() {
        let engine = engine();
        let mut json = serde_json::json!({
            "logs": [
                "Connected to 192.168.0.1",
                "Using token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
            ]
        });
        let stats = engine.redact_json(&mut json);
        assert!(stats.fields_redacted >= 2);
    }

    #[test]
    fn test_redact_json_allowlist() {
        let engine = engine();
        let mut json = serde_json::json!({
            "machine_id": "alice@example.com",  // should NOT be redacted (allowlisted)
            "notes": "alice@example.com"         // should BE redacted
        });
        let stats = engine.redact_json(&mut json);
        // machine_id should be preserved
        assert_eq!(json["machine_id"], "alice@example.com");
        // notes should be redacted
        let notes = json["notes"].as_str().unwrap();
        assert!(notes.contains("[REDACTED:email]"));
        assert!(stats.fields_redacted > 0);
    }

    #[test]
    fn test_redact_json_clean() {
        let engine = engine();
        let mut json = serde_json::json!({
            "cpu": 42.0,
            "mem": 67.2,
            "disk_pct": 80.0
        });
        let stats = engine.redact_json(&mut json);
        assert_eq!(stats.fields_redacted, 0);
    }

    // ========================================================================
    // Stats tests
    // ========================================================================

    #[test]
    fn test_stats_rule_matches() {
        let engine = engine();
        let input =
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig and password=hunter2secret";
        let (_, stats) = engine.redact_text(input);
        assert!(stats.rule_matches.len() >= 2);
    }

    #[test]
    fn test_stats_serialization() {
        let stats = RedactionStats {
            fields_redacted: 3,
            bytes_redacted: 42,
            rule_matches: vec![("email".to_string(), 2)],
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: RedactionStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields_redacted, 3);
    }

    // ========================================================================
    // Engine configuration tests
    // ========================================================================

    #[test]
    fn test_custom_rules() {
        let rules = vec![RedactionRule {
            name: "custom".to_string(),
            pattern: r"SSN:\s*\d{3}-\d{2}-\d{4}".to_string(),
            replacement: "[REDACTED:ssn]".to_string(),
            description: "Social Security Number".to_string(),
        }];
        let engine = RedactionEngine::with_rules(rules, "custom-v1");
        let (output, stats) = engine.redact_text("SSN: 123-45-6789");
        assert!(output.contains("[REDACTED:ssn]"));
        assert!(stats.fields_redacted > 0);
        assert_eq!(engine.rules_version, "custom-v1");
    }

    #[test]
    fn test_add_allowlist() {
        let mut engine = engine();
        engine.add_allowlist(&["notes"]);

        let mut json = serde_json::json!({
            "notes": "alice@example.com"
        });
        let stats = engine.redact_json(&mut json);
        // notes is now allowlisted
        assert_eq!(json["notes"], "alice@example.com");
        assert_eq!(stats.fields_redacted, 0);
    }

    #[test]
    fn test_invalid_regex_skipped() {
        let rules = vec![
            RedactionRule {
                name: "bad".to_string(),
                pattern: r"[invalid".to_string(), // bad regex
                replacement: "x".to_string(),
                description: "bad".to_string(),
            },
            RedactionRule {
                name: "good".to_string(),
                pattern: r"hello".to_string(),
                replacement: "world".to_string(),
                description: "good".to_string(),
            },
        ];
        let engine = RedactionEngine::with_rules(rules, "test");
        assert_eq!(engine.rule_count(), 1); // bad rule skipped
    }

    // ========================================================================
    // Store integration tests
    // ========================================================================

    #[test]
    fn test_redact_and_log() {
        let store = Arc::new(vc_store::VcStore::open_memory().unwrap());
        let engine = RedactionEngine::new().with_store(store.clone());

        let mut json = serde_json::json!({
            "log": "password=supersecretvalue123"
        });
        let stats = engine.redact_and_log("orko", "sysmoni", &mut json);
        assert!(stats.fields_redacted > 0);

        // Check redaction event was logged
        let events = store.list_redaction_events(Some("orko"), 10).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_redact_and_log_clean_no_event() {
        let store = Arc::new(vc_store::VcStore::open_memory().unwrap());
        let engine = RedactionEngine::new().with_store(store.clone());

        let mut json = serde_json::json!({ "cpu": 42.0 });
        let stats = engine.redact_and_log("orko", "sysmoni", &mut json);
        assert_eq!(stats.fields_redacted, 0);

        // No event logged for clean data
        let events = store.list_redaction_events(Some("orko"), 10).unwrap();
        assert_eq!(events.len(), 0);
    }

    // ========================================================================
    // RedactionRule serialization
    // ========================================================================

    #[test]
    fn test_redaction_rule_serialization() {
        let rule = RedactionRule {
            name: "test".to_string(),
            pattern: r"\d+".to_string(),
            replacement: "[NUM]".to_string(),
            description: "Numbers".to_string(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: RedactionRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
    }
}
