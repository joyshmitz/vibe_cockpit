use std::path::PathBuf;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

static INIT: Once = Once::new();

/// Initialize tracing once for integration tests.
pub fn init_tracing() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(filter)
            .init();
    });
}

/// Generate a unique temporary DuckDB path for a test.
pub fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("vc_{test_name}_{nanos}.duckdb"))
}

/// Build a default config with a test-scoped DB path.
pub fn temp_config(test_name: &str) -> vc_config::VcConfig {
    let mut config = vc_config::VcConfig::default();
    config.global.db_path = temp_db_path(test_name);
    config
}
