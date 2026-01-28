-- Machine registry expansion
-- Migration 002: Add machine registry columns + machine_tools table

-- Extend machines table
ALTER TABLE machines ADD COLUMN display_name TEXT;
ALTER TABLE machines ADD COLUMN ssh_key_path TEXT;
ALTER TABLE machines ADD COLUMN ssh_port INTEGER DEFAULT 22;
ALTER TABLE machines ADD COLUMN os_type TEXT;
ALTER TABLE machines ADD COLUMN arch TEXT;
ALTER TABLE machines ADD COLUMN added_at TIMESTAMP DEFAULT current_timestamp;
ALTER TABLE machines ADD COLUMN last_probe_at TIMESTAMP;
ALTER TABLE machines ADD COLUMN status TEXT DEFAULT 'unknown';
ALTER TABLE machines ADD COLUMN metadata TEXT;

-- Tool availability per machine
CREATE TABLE IF NOT EXISTS machine_tools (
    machine_id TEXT,
    tool_name TEXT,
    tool_path TEXT,
    tool_version TEXT,
    is_available BOOLEAN DEFAULT TRUE,
    probed_at TIMESTAMP,
    PRIMARY KEY (machine_id, tool_name)
);
