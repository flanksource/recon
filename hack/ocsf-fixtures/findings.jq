# Convert a scan-report fixture's findings from recon's old shape to OCSF
# Detection Findings.
#
# One-off, run once per fixture:
#   jq -f hack/ocsf-fixtures/findings.jq app/reports/sample.json
#
# The mapping is the same one the Go adapters perform, so a fixture converted
# here and a finding the server emits today render identically:
#   templateId  -> checkId and finding_info.uid
#   name        -> finding_info.title
#   severity    -> severity_id on OCSF's scale
#   type        -> engine and metadata.product.name
#   matcherName -> status_code (prowler's, which is the only one that was ever
#                  an OCSF value; the others get real homes of their own)
#   raw.info.description -> finding_info.desc
#   remediation + reference -> remediation{desc, references}
#   curl/extracted/request/response -> one evidences[] entry

def severity_id:
  {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[.] // 0;

# `type` held two different facts. prowler, trivy and inspec wrote the engine
# there; nuclei wrote the protocol the template speaks — "http", "dns" — so the
# column meant "engine" for three engines and "protocol" for the fourth. The
# engine is now its own field and the protocol goes to OCSF's escape hatch.
def engines: ["prowler", "trivy", "inspec", "nuclei"];
def engine_of: if (. as $t | engines | index($t)) then . else "nuclei" end;
def protocol_of: if (. as $t | engines | index($t)) then null else . end;

def epoch_millis:
  # fromdateiso8601 rejects fractional seconds, which these stamps carry.
  (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) * 1000;

def prune: walk(if type == "object" then with_entries(select(.value != null)) else . end);

def evidence:
  {
    name: (if (.type == "prowler") then null else .matcherName end),
    url: (if .matchedAt then {url_string: .matchedAt} else null end),
    http_request: (if .request then {args: .request} else null end),
    http_response: (if .response then {message: .response} else null end),
    data: (
      if (.curl or ((.extracted // []) | length) > 0)
      then {curl: .curl, extracted: .extracted}
      else null end
    ),
  }
  | with_entries(select(.value != null))
  # An entry needs one of the attributes OCSF's at_least_one constraint names,
  # and `name` is not among them.
  | if (keys - ["name"] | length) > 0 then [.] else [] end;

# What the finding is about, for a fixture whose record named nothing. The
# server synthesises the same reference — see api.Finding.ResourceFallback —
# so every finding arrives with at least one subject and no consumer has to
# derive an identity of its own.
def fallback_resource:
  [{uid: .host, name: (.matchedAt // .host), type: (.type | engine_of)}];

.findings |= map(
  . as $f
  | {
      scanId: $f.scanId,
      lineNo: $f.lineNo,
      checkId: $f.templateId,
      engine: ($f.type | engine_of),
      # Recon's vocabulary rather than the engine's: a verdict a human still
      # owes a decision on. Absent means fail, which is what everything was
      # before the distinction existed.
      verdict: (
        if ($f.type == "prowler" and $f.matcherName == "MANUAL") then "manual" else null end
      ),
      host: $f.host,
      matchedAt: $f.matchedAt,
      tags: $f.tags,

      class_uid: 2004,
      category_uid: 2,
      type_uid: 200401,
      activity_id: 1,
      severity_id: ($f.severity | severity_id),
      status_id: 1,
      # Only prowler's, because only prowler's was already an OCSF status code.
      # nuclei means the matcher that fired, which is a different fact and gets
      # a different home below — writing both here is the conflation this
      # redesign exists to remove.
      status_code: (if ($f.type == "prowler") then $f.matcherName else null end),
      time: (if $f.timestamp then ($f.timestamp | epoch_millis) else null end),

      finding_info: {
        uid: $f.templateId,
        title: $f.name,
        desc: ($f.raw.info.description // $f.raw.description),
        types: $f.tags,
      },
      metadata: {
        version: "1.5.0",
        event_code: $f.templateId,
        product: {name: ($f.type | engine_of), vendor_name: "flanksource-recon"},
        # prowler audits a cloud account, so it declares the profile that makes
        # cloud.provider required of it.
        profiles: (if ($f.type == "prowler") then ["cloud"] else null end),
      },
      # prowler reports the account it audited at the event level, which is
      # where OCSF wants it and the only place a resource key can get a scope.
      cloud: (
        if ($f.type == "prowler")
        then {provider: ($f.templateId | split("/")[0]), account: {uid: $f.host}}
        else null end
      ),
      unmapped: (
        {
          protocol: ($f.type | protocol_of),
          matcher_name: (if ($f.type == "prowler") then null else $f.matcherName end),
        }
        | with_entries(select(.value != null))
        | if length > 0 then . else null end
      ),
      remediation: (
        if ($f.remediation or (($f.reference // []) | length) > 0)
        then {desc: $f.remediation, references: $f.reference}
        else null end
      ),
      # prowler contributes none: its records name resources, not exchanges,
      # and an ARN in `url` would be claiming to be a URL.
      evidences: (if ($f.type == "prowler") then [] else ($f | evidence) end),
      resources: (
        if (($f.resources // []) | length) > 0
        then $f.resources
        else ($f | fallback_resource) end
      ),
    }
)
| prune
