mod common;

use common::{init_tracing, temp_config};

#[test]
fn test_temp_config_defaults() {
    init_tracing();
    let config = temp_config("config_smoke");
    assert!(config.global.poll_interval_secs > 0);
}
