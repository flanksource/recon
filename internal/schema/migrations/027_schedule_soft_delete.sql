-- phase: pre
-- dependsOn: 026_scan_creators.sql
--
-- Remove the preview-era snapshot; names are read from retained schedule rows.
ALTER TABLE IF EXISTS scans DROP COLUMN IF EXISTS creator_schedule_name;
