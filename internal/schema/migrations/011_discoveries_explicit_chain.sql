-- phase: post
-- PostgreSQL check-expression changes are not reconciled on existing tables by
-- the Atlas realm diff, so replace the legacy full|targeted constraint explicitly.
ALTER TABLE discoveries DROP CONSTRAINT IF EXISTS discoveries_chain_enum;

ALTER TABLE discoveries
  ADD CONSTRAINT discoveries_chain_enum
  CHECK (chain IN ('full', 'targeted', 'explicit'));
