-- dependsOn: 011_discoveries_explicit_chain.sql
ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_class_enum;
ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_profiles_known;
ALTER TABLE discoveries DROP CONSTRAINT IF EXISTS discoveries_chain_enum;
ALTER TABLE engine_profiles DROP CONSTRAINT IF EXISTS engine_profiles_kind_enum;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_phase_enum;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_severity_enum;
