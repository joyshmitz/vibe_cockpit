-- Migration 013: Alert delivery log
-- Created: 2026-01-30
-- Purpose: Track alert deliveries across channels for auditing and retry logic

CREATE TABLE IF NOT EXISTS alert_delivery_log (
    id INTEGER PRIMARY KEY,
    alert_id TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    delivered_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    duration_ms BIGINT
);
