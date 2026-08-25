package store

// severityText renders OCSF's severity_id back into recon's vocabulary, in SQL.
//
// findings stores the OCSF scale, which is what the schema defines and what any
// other OCSF consumer expects. finding_states, checks and the counts the UI
// groups by store recon's ladder, which is lowercase and has no Fatal rung.
// Translating in one place keeps the two from drifting apart the way two copies
// of a mapping always do.
//
// Fatal maps to critical rather than to unknown for the same reason api's
// SeverityOf does: a finding an engine considered the most severe thing it found
// must not be filed under "nobody could classify this".
const severityText = `CASE f.severity_id
    WHEN 6 THEN 'critical'
    WHEN 5 THEN 'critical'
    WHEN 4 THEN 'high'
    WHEN 3 THEN 'medium'
    WHEN 2 THEN 'low'
    WHEN 1 THEN 'info'
    ELSE 'unknown'
  END`

// severityRank orders findings most-severe-first under ASC.
//
// OCSF numbers its scale upwards — critical is 5, informational is 1 — and every
// recon listing has always meant ascending as most severe first. Sorting on
// severity_id directly would reverse the default order of every findings page,
// which is the kind of change that looks like a data problem rather than a sort
// problem.
const severityRank = `CASE severity_id
    WHEN 6 THEN 0
    WHEN 5 THEN 0
    WHEN 4 THEN 1
    WHEN 3 THEN 2
    WHEN 2 THEN 3
    WHEN 1 THEN 4
    ELSE 5
  END`
