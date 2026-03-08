#!/bin/bash
set -euo pipefail

# Ensure we have .beads directory
br init || true

echo "Creating root task..."
ID_ROOT=$(br create "Migrate vibe_cockpit from Tokio to Asupersync" -p 0 -t task --json | jq -r '.id')
br update "$ID_ROOT" --notes "We must replace ANY AND ALL usage of tokio with the /dp/asupersync project in an optimal, rigorous way. This involves adopting Asupersync's structured concurrency model (Cx, regions, obligations), replacing tokio primitives, and handling third-party crates (like axum, russh) either via asupersync-tokio-compat or direct ports to asupersync equivalents."

echo "Creating Phase 1: Dependencies and Runtime..."
ID_DEPS=$(br create "Phase 1: Replace tokio dependencies and scaffold Asupersync runtime" -p 0 -t task --json | jq -r '.id')
br dep add "$ID_DEPS" "$ID_ROOT"
br update "$ID_DEPS" --notes "Background: The project must drop Tokio completely in favor of /dp/asupersync.
Tasks:
1. Modify Cargo.toml workspace and all crates to remove tokio and add asupersync (path = '/dp/asupersync').
2. Replace #[tokio::main] in vc_cli/src/main.rs with an explicit Asupersync runtime initialization (e.g., asupersync::runtime::Runtime::new().block_on(...)).
3. Establish the root Region and Cx capability token to pass down to sub-components, enforcing structured concurrency."

echo "Creating Phase 2a: Migrate vc_collect..."
ID_COLLECT=$(br create "Phase 2a: Migrate vc_collect to Asupersync" -p 1 -t task --json | jq -r '.id')
br dep add "$ID_COLLECT" "$ID_DEPS"
br dep add "$ID_COLLECT" "$ID_ROOT"
br update "$ID_COLLECT" --notes "Background: vc_collect heavily relies on Tokio's process, time, and sync primitives, plus the russh crate for SSH.
Tasks:
1. Replace tokio::process::Command with asupersync::process::Command.
2. Replace tokio::time::timeout and sleep with asupersync::time utilities.
3. Migrate internal Mutex usage to asupersync::sync::Mutex.
4. Handling russh: Since russh is deeply tied to tokio, we must wrap it using asupersync-tokio-compat to bridge the network streams and runtime, ensuring explicit cancellation semantics via Cx propagate properly."

echo "Creating Phase 2b: Migrate vc_alert..."
ID_ALERT=$(br create "Phase 2b: Migrate vc_alert to Asupersync" -p 1 -t task --json | jq -r '.id')
br dep add "$ID_ALERT" "$ID_DEPS"
br dep add "$ID_ALERT" "$ID_ROOT"
br update "$ID_ALERT" --notes "Background: vc_alert uses Tokio channels and process execution for desktop notifications.
Tasks:
1. Replace tokio::sync::mpsc with asupersync::channel::mpsc.
2. Migrate background alert dispatch loops to use structured regions (region.spawn) so they are naturally bound to the application lifecycle and cleanly cancelled on shutdown.
3. Replace tokio::process::Command for desktop notifications (notify-send/osascript) with asupersync::process."

echo "Creating Phase 2c: Migrate vc_web..."
ID_WEB=$(br create "Phase 2c: Migrate vc_web to Asupersync HTTP stack" -p 1 -t task --json | jq -r '.id')
br dep add "$ID_WEB" "$ID_DEPS"
br dep add "$ID_WEB" "$ID_ROOT"
br update "$ID_WEB" --notes "Background: vc_web relies on Axum and tokio::net::TcpListener for its HTTP server.
Tasks:
1. Evaluate if asupersync::web can directly replace axum for our endpoints. If parity is sufficient, rewrite the router using asupersync::web to get pure structured concurrency.
2. If axum is required, run it inside the asupersync-tokio-compat bridge, using asupersync::net::tcp::TcpListener and routing it through the compatibility layer.
3. Replace tokio::signal::ctrl_c with asupersync::signal handling."

echo "Creating Phase 2d: Migrate vc_mcp..."
ID_MCP=$(br create "Phase 2d: Migrate vc_mcp to Asupersync IO" -p 1 -t task --json | jq -r '.id')
br dep add "$ID_MCP" "$ID_DEPS"
br dep add "$ID_MCP" "$ID_ROOT"
br update "$ID_MCP" --notes "Background: vc_mcp implements the Model Context Protocol over stdio.
Tasks:
1. Replace standard stdio looping/blocking reads with asupersync::io structured streams.
2. Replace Tokio select! macros with Asupersync structured race/select patterns.
3. Ensure the JSON-RPC execution loop respects the Cx cancellation token for graceful shutdown."

echo "Creating Phase 3: Migrate all tests..."
ID_TESTS=$(br create "Phase 3: Migrate all test suites to Asupersync determinism" -p 2 -t task --json | jq -r '.id')
br dep add "$ID_TESTS" "$ID_COLLECT"
br dep add "$ID_TESTS" "$ID_ALERT"
br dep add "$ID_TESTS" "$ID_WEB"
br dep add "$ID_TESTS" "$ID_MCP"
br dep add "$ID_TESTS" "$ID_ROOT"
br update "$ID_TESTS" --notes "Background: All crates currently use #[tokio::test].
Tasks:
1. Strip #[tokio::test] from vc_query, vc_store, vc_oracle, vc_cli, vc_web, etc.
2. Replace them with Asupersync's test runner equivalent (or a manual asupersync::runtime::run() block).
3. Utilize Asupersync's deterministic test labs (src/lab) to verify the concurrent logic in vc_collect and vc_alert, ensuring our adaptive scheduler and channel operations are robust."

echo "All beads created and dependencies linked."
br dep cycles
