-- Migration 012: Add missing columns to health_factors and health_summary
-- Created: 2026-01-30
-- Purpose: Extend health tables with weight, factor_count, severity counts

-- Add weight column to health_factors (created in 001_initial_schema without it)
-- DuckDB doesn't support ADD COLUMN with NOT NULL, so use nullable
ALTER TABLE health_factors ADD COLUMN IF NOT EXISTS weight REAL DEFAULT 1.0;

-- Add missing columns to health_summary
ALTER TABLE health_summary ADD COLUMN IF NOT EXISTS factor_count INTEGER DEFAULT 0;
ALTER TABLE health_summary ADD COLUMN IF NOT EXISTS critical_count INTEGER DEFAULT 0;
ALTER TABLE health_summary ADD COLUMN IF NOT EXISTS warning_count INTEGER DEFAULT 0;
