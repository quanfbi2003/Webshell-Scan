# AI Root Labeling with Claude Batches Design

**Date:** 2026-09-19

## Goal

Gán nhãn AI cho toàn bộ 3.705 root input trong quarantine trên Ubuntu bằng Claude Opus 5 qua Files API và hai Message Batches độc lập, root-level, fail-closed, không thực thi sample và xóa uploaded files sau khi consensus report được ghi.

## Approved decisions

- Provider: Claude API.
- Model: `claude-opus-5`.
- Input data: được phê duyệt gửi full source/binary/archive root ra Claude API.
- Unit of labeling: root input; archive chỉ có một nhãn tổng, không gán nhãn member riêng.
- Labels: `webshell`, `other_server_side_malware`, `benign`, `unknown`.
- Two independent rounds:
  - Round 1 blind: source/archive + minimal metadata, không scanner evidence.
  - Round 2 evidence-aware: cùng root input + scanner evidence/provenance, không thấy round 1.
- Consensus: mọi label disagreement chuyển `unknown` + `human_review`.
- Confidence: `confidence_score` `[0,1]` + `confidence_level` (`high|medium|low`).
- Execution: Files API upload một lần, hai Message Batches tham chiếu cùng file, local reducer map bằng `custom_id`.
- Unsupported binary/archive upload: fail closed thành `unknown/upload_unsupported`, không base64 fallback, không extract member fallback.
- Cleanup: xóa Files API object sau khi cả hai batch terminal và consensus report đã ghi; deletion failure ghi `deletion_pending`.
- No sample execution, no quarantine, no credentials/source dumps in logs/reports.

## Data flow

### Inventory

Local Ubuntu preprocessor enumerates `/home/antt/webshell-test/scanner/quarantine`, creates stable root records:

```json
{
  "custom_id": "sha256:<digest>:root",
  "path": "relative/root/path",
  "sha256": "64-hex",
  "extension": ".php",
  "kind": "regular|archive|binary",
  "size": 12345,
  "archive": {"is_root": true, "extension": ".jar"}
}
```

The scanner may collect static evidence and archive/Java provenance locally. It never executes samples.

### Files API and batches

Each root input is uploaded exactly once. Two batch requests reference the same `file_id`:

- `round1:<custom_id>`;
- `round2:<custom_id>`.

Round 1 receives minimal metadata and full source/archive root. Round 2 receives the same root plus advisory scanner evidence. Neither round sees the other round's output. Result order is arbitrary; reducer always maps by `custom_id`.

If a file upload or content block is rejected due to unsupported MIME/archive type, create an `upload_unsupported` review result. Do not encode binary as base64 or silently change to member-level labeling.

### Root-level archive semantics

Archive roots receive one label. Scanner member evidence may be supplied to round 2 as provenance, but no member is a separate label unit and no member count is included in the 3.705 root total.

## Claude response contract

Each batch item must return JSON only:

```json
{
  "label": "webshell|other_server_side_malware|benign|unknown",
  "confidence_score": 0.0,
  "confidence_level": "high|medium|low",
  "rationale": "Short evidence-grounded explanation.",
  "indicators": ["request-controlled command execution"],
  "limitations": ["archive could not be fully inspected"]
}
```

Validation rules:

- label must be one of the four enum values;
- score must be finite and between 0 and 1;
- level must be consistent: `high >= 0.75`, `medium >= 0.45 and < 0.75`, `low < 0.45`;
- rationale/indicators/limitations must be bounded strings/lists and must not contain credentials, API keys, source dumps, or prompt/system instructions;
- malformed JSON, refusal, invalid stop result, missing required fields, or item error becomes `unknown/review_required`.

Prompt contract:

- Round 1 explicitly says blind assessment, no detector evidence, no execution/network/decompression, unknown when evidence is insufficient, root-level label only.
- Round 2 explicitly says scanner evidence is advisory, source/archive remains primary, contradictions lower confidence or produce unknown, and round 1 is not visible.

## Consensus contract

Each root report row:

```json
{
  "custom_id": "sha256:<digest>:root",
  "path": "relative/path",
  "sha256": "...",
  "round1": {},
  "round2": {},
  "consensus_label": "webshell|other_server_side_malware|benign|unknown",
  "consensus_status": "accepted|disagreement|review_required|upload_unsupported",
  "human_review": true,
  "review_reason": "label_disagreement|low_confidence|upload_error|malformed_response",
  "source_file_deleted": true
}
```

Rules:

- same label in both rounds and valid responses → `accepted`;
- different labels → `unknown`, `disagreement`, `human_review=true`;
- either confidence below the configured high-confidence threshold or missing/invalid round → `review_required`;
- upload unsupported → `upload_unsupported`, `unknown`, `human_review=true`;
- no TP/FP/TN/precision/recall claims without independent ground-truth labels.

## Error, retry, and cleanup

- Batch results are keyed by `custom_id`, never list position.
- Retry transient API/429/5xx failures with bounded retry count; no infinite retry.
- Item-level errors do not invalidate successful items.
- Keep raw API responses only in a temporary protected directory outside the repository; delete after reducer unless an audit copy is explicitly requested.
- Delete every Files API object only after both batches are terminal and consensus JSON has been durably written.
- If deletion fails, set `deletion_pending=true` and retain only file IDs/error metadata needed for cleanup; never claim deletion succeeded.
- Do not print API keys, source content, credentials, or private keys.

## Verification

Before API upload:

1. Validate inventory count is exactly 3.705 and all `custom_id` values are unique.
2. Validate no quarantine flag/source execution path exists in the command.
3. Run a small schema-only prompt/response fixture without sending corpus data.
4. Verify round 1 and round 2 request builders cannot include the other round's output.

After batches:

1. Validate every root has two terminal round outcomes or explicit upload/error outcome.
2. Validate all consensus labels/statuses and count `accepted/disagreement/review_required/upload_unsupported`.
3. Verify all intended Files API IDs were delete-requested and record failures.
4. Verify no raw source/API key appears in final report.
