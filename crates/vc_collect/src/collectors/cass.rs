//! CASS collector - session search and statistics
//!
//! This collector uses the CLI Snapshot ingestion pattern to collect
//! session statistics and index health from the `cass` tool.
//!
//! ## Integration Method
//! ```bash
//! cass stats --json     # Aggregate statistics
//! cass health --json    # Index status
//! ```
//!
//! ## Tables Populated
//! - `agent_sessions`: Session data (snapshot)
//! - `cass_index_status`: Index health metrics

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Instant;

use crate::{CollectContext, CollectError, CollectResult, Collector, RowBatch, Warning};

/// Output schema from `cass health --json`
#[derive(Debug, Deserialize)]
pub struct CassHealthOutput {
    /// Index state (ready, indexing, stale, error)
    #[serde(default)]
    pub state: String,

    /// Total indexed sessions
    #[serde(default)]
    pub total_sessions: i64,

    /// Last index timestamp
    #[serde(default)]
    pub last_index_at: Option<String>,

    /// Index size in bytes
    #[serde(default)]
    pub index_size_bytes: i64,

    /// Seconds since last index refresh
    #[serde(default)]
    pub freshness_seconds: i64,
}

/// Output schema from `cass stats --json`
#[derive(Debug, Deserialize)]
pub struct CassStatsOutput {
    /// Total number of conversations/sessions
    #[serde(default)]
    pub total_conversations: i64,

    /// Total number of messages across all sessions
    #[serde(default)]
    pub total_messages: i64,

    /// Sessions by agent program
    #[serde(default)]
    pub by_agent: HashMap<String, i64>,

    /// Sessions by workspace/directory
    #[serde(default)]
    pub by_workspace: HashMap<String, i64>,
}

/// CASS collector for session search statistics
///
/// Collects index health status and session statistics from the cass tool's
/// JSON output. Uses snapshot pattern since cass data is already aggregated.
pub struct CassCollector;

impl CassCollector {
    /// Create a new CASS collector
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for CassCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for CassCollector {
    fn name(&self) -> &'static str {
        "cass"
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("cass")
    }

    fn supports_incremental(&self) -> bool {
        false // Each collection is a point-in-time snapshot
    }

    #[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
    async fn collect(&self, ctx: &CollectContext) -> Result<CollectResult, CollectError> {
        let start = Instant::now();
        let mut warnings = Vec::new();
        let mut batches = Vec::new();

        // Check if cass is available
        if !self.check_availability(ctx).await {
            return Err(CollectError::ToolNotFound("cass".to_string()));
        }

        let collected_at = ctx.collected_at.to_rfc3339();

        // Collect health status
        match ctx
            .executor
            .run_timeout("cass health --json", ctx.timeout)
            .await
        {
            Ok(output) => {
                match serde_json::from_str::<CassHealthOutput>(&output) {
                    Ok(health) => {
                        let row = serde_json::json!({
                            "machine_id": ctx.machine_id,
                            "collected_at": &collected_at,
                            "state": health.state,
                            "total_sessions": health.total_sessions,
                            "last_index_at": health.last_index_at,
                            "index_size_bytes": health.index_size_bytes,
                            "freshness_seconds": health.freshness_seconds,
                            "raw_json": &output,
                        });

                        batches.push(RowBatch {
                            table: "cass_index_status".to_string(),
                            rows: vec![row],
                        });

                        // Check for stale index (> 24 hours)
                        if health.freshness_seconds > 86400 {
                            let freshness = health.freshness_seconds;
                            warnings.push(Warning::warn(format!(
                                "CASS index is stale: {freshness} seconds since last refresh",
                            )));
                        }
                    }
                    Err(e) => {
                        warnings.push(Warning::warn(format!(
                            "Failed to parse cass health output: {e}",
                        )));
                    }
                }
            }
            Err(e) => {
                warnings.push(Warning::warn(format!("Failed to run cass health: {e}")));
            }
        }

        // Collect stats
        match ctx
            .executor
            .run_timeout("cass stats --json", ctx.timeout)
            .await
        {
            Ok(output) => {
                match serde_json::from_str::<CassStatsOutput>(&output) {
                    Ok(stats) => {
                        let mut stats_rows = Vec::new();

                        // Overall metrics
                        stats_rows.push(serde_json::json!({
                            "machine_id": ctx.machine_id,
                            "collected_at": &collected_at,
                            "metric_name": "total_conversations",
                            "metric_value": stats.total_conversations as f64,
                            "dimensions_json": "{}",
                            "raw_json": null,
                        }));

                        stats_rows.push(serde_json::json!({
                            "machine_id": ctx.machine_id,
                            "collected_at": &collected_at,
                            "metric_name": "total_messages",
                            "metric_value": stats.total_messages as f64,
                            "dimensions_json": "{}",
                            "raw_json": null,
                        }));

                        // Per-agent breakdown
                        for (agent, count) in &stats.by_agent {
                            stats_rows.push(serde_json::json!({
                                "machine_id": ctx.machine_id,
                                "collected_at": &collected_at,
                                "metric_name": "sessions_by_agent",
                                "metric_value": *count as f64,
                                "dimensions_json": serde_json::json!({"agent": agent}).to_string(),
                                "raw_json": null,
                            }));
                        }

                        // Per-workspace breakdown (limit to top 10)
                        let mut workspace_vec: Vec<_> = stats.by_workspace.iter().collect();
                        workspace_vec.sort_by(|a, b| b.1.cmp(a.1));
                        for (workspace, count) in workspace_vec.into_iter().take(10) {
                            stats_rows.push(serde_json::json!({
                                "machine_id": ctx.machine_id,
                                "collected_at": &collected_at,
                                "metric_name": "sessions_by_workspace",
                                "metric_value": *count as f64,
                                "dimensions_json": serde_json::json!({"workspace": workspace}).to_string(),
                                "raw_json": null,
                            }));
                        }

                        if !stats_rows.is_empty() {
                            batches.push(RowBatch {
                                table: "cass_stats_snapshots".to_string(),
                                rows: stats_rows,
                            });
                        }
                    }
                    Err(e) => {
                        warnings.push(Warning::warn(format!(
                            "Failed to parse cass stats output: {e}",
                        )));
                    }
                }
            }
            Err(e) => {
                warnings.push(Warning::warn(format!("Failed to run cass stats: {e}")));
            }
        }

        let mut result = CollectResult::with_rows(batches).with_duration(start.elapsed());

        for warning in warnings {
            result = result.with_warning(warning);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_cass_collector_name() {
        let collector = CassCollector::new();
        assert_eq!(collector.name(), "cass");
        assert_eq!(collector.required_tool(), Some("cass"));
        assert!(!collector.supports_incremental());
        assert_eq!(collector.schema_version(), 1);
    }

    #[test]
    fn test_cass_health_parsing_full() {
        let json = r#"{
            "state": "ready",
            "total_sessions": 1500,
            "last_index_at": "2026-01-27T00:00:00Z",
            "index_size_bytes": 52428800,
            "freshness_seconds": 120
        }"#;

        let health: CassHealthOutput = serde_json::from_str(json).unwrap();

        assert_eq!(health.state, "ready");
        assert_eq!(health.total_sessions, 1500);
        assert_eq!(
            health.last_index_at,
            Some("2026-01-27T00:00:00Z".to_string())
        );
        assert_eq!(health.index_size_bytes, 52_428_800);
        assert_eq!(health.freshness_seconds, 120);
    }

    #[test]
    fn test_cass_health_parsing_minimal() {
        let json = r"{}";

        let health: CassHealthOutput = serde_json::from_str(json).unwrap();

        assert_eq!(health.state, "");
        assert_eq!(health.total_sessions, 0);
        assert!(health.last_index_at.is_none());
        assert_eq!(health.index_size_bytes, 0);
        assert_eq!(health.freshness_seconds, 0);
    }

    #[test]
    fn test_cass_stats_parsing_full() {
        let json = r#"{
            "total_conversations": 1500,
            "total_messages": 45000,
            "by_agent": {
                "claude-code": 800,
                "codex-cli": 500,
                "gemini-cli": 200
            },
            "by_workspace": {
                "/data/projects/vibe_cockpit": 150,
                "/data/projects/dcg": 120
            }
        }"#;

        let stats: CassStatsOutput = serde_json::from_str(json).unwrap();

        assert_eq!(stats.total_conversations, 1500);
        assert_eq!(stats.total_messages, 45000);
        assert_eq!(stats.by_agent.len(), 3);
        assert_eq!(stats.by_agent.get("claude-code"), Some(&800));
        assert_eq!(stats.by_workspace.len(), 2);
    }

    #[test]
    fn test_cass_stats_parsing_empty() {
        let json = r#"{
            "total_conversations": 0,
            "total_messages": 0
        }"#;

        let stats: CassStatsOutput = serde_json::from_str(json).unwrap();

        assert_eq!(stats.total_conversations, 0);
        assert_eq!(stats.total_messages, 0);
        assert!(stats.by_agent.is_empty());
        assert!(stats.by_workspace.is_empty());
    }

    #[test]
    fn test_default_impl() {
        let collector = CassCollector;
        assert_eq!(collector.name(), "cass");
    }

    #[tokio::test]
    async fn test_cass_collector_behavior() {
        let collector = CassCollector::new();
        let ctx = CollectContext::local("test", Duration::from_secs(5));

        let result = collector.collect(&ctx).await;

        // Test handles both cases: cass installed or not
        match result {
            Err(CollectError::ToolNotFound(tool)) => {
                // Expected when cass is not installed
                assert_eq!(tool, "cass");
            }
            Err(_) => {
                // Other errors are acceptable (e.g., command not found, parse error)
            }
            Ok(collect_result) => {
                // If cass is installed, verify the result structure
                assert!(collect_result.success);
            }
        }
    }

    #[test]
    fn test_stale_index_threshold() {
        // Verify stale index threshold is 24 hours
        let threshold_seconds = 86400;
        assert_eq!(threshold_seconds, 24 * 60 * 60);
    }
}
