# Dependency Upgrade Log

**Date:** 2026-02-20  |  **Project:** vibe_cockpit  |  **Language:** Rust

## Summary
- **Updated:** 12  |  **Skipped:** 0  |  **Failed:** 0  |  **Already latest:** 16

## Toolchain

### Rust nightly (latest)
- **Pinned:** Created `rust-toolchain.toml` with `channel = "nightly"` + rustfmt, clippy components
- **Version:** rustc 1.95.0-nightly (7f99507f5 2026-02-19)

## Breaking Upgrades (required code changes)

### toml: 0.8 -> 1.0.3
- **Breaking:** Serializer/Deserializer API redesign, `Buffer` replaces `String`
- **Impact:** None -- project only uses `toml::from_str`, `toml::to_string_pretty`, `toml::de::Error`
- **Code changes:** None
- **Tests:** Pass

### ratatui: 0.29 -> 0.30.0
- **Breaking:** Modularization release, `block::Title` removed, `block::Position` moved
- **Impact:** None -- project doesn't use removed/moved APIs
- **Code changes:** None
- **Tests:** Pass

### crossterm: 0.28 -> 0.29.0
- **Breaking:** KeyModifiers display format change
- **Impact:** None
- **Code changes:** None
- **Tests:** Pass

### rand: 0.8 -> 0.10.0
- **Breaking:** `gen()` -> `random()`, `gen_range()` -> `random_range()`, `gen_bool()` -> `random_bool()`, `thread_rng()` -> `rng()`, `from_entropy()` removed, methods moved to `RngExt` trait
- **Code changes:** Updated `vc_oracle/src/evolution.rs` and `vc_oracle/src/experiment.rs`:
  - Import `RngExt` trait alongside `Rng`
  - `rng.r#gen::<f64>()` -> `rng.random::<f64>()`
  - `rng.r#gen_bool()` -> `rng.random_bool()`
  - `rng.gen_range()` -> `rng.random_range()`
  - `rand::thread_rng()` -> `rand::rng()`
  - `StdRng::from_entropy()` -> `StdRng::from_rng(&mut rand::rng())`
- **Tests:** Pass

### reqwest: 0.12 -> 0.13.2
- **Breaking:** Default TLS switched from native-tls to rustls, `query()`/`form()` now feature-gated
- **Impact:** None -- project uses `features = ["json"]` which still works, and doesn't use `query()`/`form()` features
- **Code changes:** None
- **Benefit:** Dropped OpenSSL dependency in favor of pure-Rust TLS (rustls)
- **Tests:** Pass

### russh: 0.45 -> 0.49.2
- **Breaking:** `authenticate_publickey` now takes `PrivateKeyWithHashAlg` instead of `Arc<PrivateKey>`, `PublicKey` moved from `russh_keys::key::PublicKey` to `russh_keys::PublicKey`
- **Code changes:** Updated `vc_collect/src/ssh.rs`:
  - `russh_keys::key::PublicKey` -> `russh_keys::PublicKey`
  - Wrap loaded key: `PrivateKeyWithHashAlg::new(Arc::new(secret_key), None)`
- **Tests:** Pass
- **Note:** russh 0.57.0 available but pinned to 0.49.2 for russh-keys 0.49.2 compatibility

### russh-keys: 0.45 -> 0.49.2
- **Breaking:** `PublicKey` re-export path changed, new `PrivateKeyWithHashAlg` type
- **Code changes:** See russh above
- **Tests:** Pass

## Semver-Compatible Bumps (no code changes needed)

### tokio: 1.44 -> 1.49
- **Tests:** Pass

### duckdb: 1.1 -> 1.4
- **Tests:** Pass

### proptest: 1.9.0 -> 1.10
- **Tests:** Pass

### uuid: 1.11 -> 1.21
- **Tests:** Pass

### regex: 1.11 -> 1.12
- **Tests:** Pass

## Already at Latest (no changes)

| Crate | Version | Status |
|-------|---------|--------|
| serde | 1.0 | Latest compatible |
| serde_json | 1.0 | Latest compatible |
| clap | 4.5 | Latest compatible |
| axum | 0.8 | Latest compatible |
| tower | 0.5 | Latest compatible |
| tower-http | 0.6 | Latest compatible |
| chrono | 0.4 | Latest compatible |
| thiserror | 2.0 | Latest compatible |
| anyhow | 1.0 | Latest compatible |
| tracing | 0.1 | Latest compatible |
| tracing-subscriber | 0.3 | Latest compatible |
| mockall | 0.14.0 | Latest stable |
| async-trait | 0.1 | Latest compatible |
| dashmap | 6.1 | Latest stable (7.0.0-rc2 skipped) |
| futures | 0.3 | Latest compatible |
| vergen-gix | 9.1.0 | Latest stable |

## Validation

- `cargo check --workspace --all-targets`: Pass
- `cargo test --workspace`: All tests pass
- `cargo fmt --check`: Pass (after formatting)
- Pre-existing clippy pedantic warnings in vc_config (not introduced by this upgrade)
