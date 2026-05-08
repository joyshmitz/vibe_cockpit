-- Reconcile ntm_sessions_snapshot column drift.
--
-- Migration 001 created ntm_sessions_snapshot with columns
--   (machine_id, collected_at, session_name, work_dir, git_branch,
--    agent_counts_json, panes_json, raw_json)
-- but the NTM collector emits (and migration 006 declares) a different shape:
--   (machine_id, collected_at, session_name, exists, attached, windows,
--    panes, agent_count, agents_json, raw_json)
-- Because 006 used CREATE TABLE IF NOT EXISTS, fresh databases retain the 001
-- shape and the row-batch persist fails with
--   "Binder Error: Table 'ntm_sessions_snapshot' does not have a column with name 'exists'"
--
-- Add the missing columns from the 006 shape. DuckDB (current) and SQLite
-- (post-translation per migrations.rs) both support ADD COLUMN with a DEFAULT
-- that backfills existing rows. The pre-existing 001 columns (work_dir,
-- git_branch, agent_counts_json, panes_json) are left in place so historical
-- rows remain readable and any out-of-tree consumer is not broken.
ALTER TABLE ntm_sessions_snapshot ADD COLUMN exists INTEGER DEFAULT 1;
ALTER TABLE ntm_sessions_snapshot ADD COLUMN attached INTEGER DEFAULT 0;
ALTER TABLE ntm_sessions_snapshot ADD COLUMN windows INTEGER DEFAULT 0;
ALTER TABLE ntm_sessions_snapshot ADD COLUMN panes INTEGER DEFAULT 0;
ALTER TABLE ntm_sessions_snapshot ADD COLUMN agent_count INTEGER DEFAULT 0;
ALTER TABLE ntm_sessions_snapshot ADD COLUMN agents_json TEXT;
