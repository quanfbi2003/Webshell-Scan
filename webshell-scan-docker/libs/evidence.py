"""Pure helpers for structured detector evidence and candidate identity."""

import hashlib
import math


_BEHAVIORAL_DETECTORS = frozenset(
    {"source_sink", "behavior_graph", "webshell_capability", "ast_df"}
)


def make_evidence(
    detector,
    score=0,
    reason=None,
    layer="raw",
    coverage="full",
    truncated=False,
    status="clean",
    rule_version=None,
    model_version=None,
):
    """Return one deterministic detector evidence record."""
    return {
        "detector": detector,
        "score": int(score),
        "reason": reason,
        "layer": layer,
        "coverage": coverage,
        "truncated": bool(truncated),
        "status": status,
        "rule_version": rule_version,
        "model_version": model_version,
    }


def _normalized_path(value):
    return str(value or "").replace("\\", "/")


def _length_delimited(parts):
    encoded = []
    for part in parts:
        value = str(part)
        value_bytes = value.encode("utf-8")
        encoded.append(str(len(value_bytes)).encode("ascii"))
        encoded.append(b":")
        encoded.append(value_bytes)
        encoded.append(b"|")
    return b"".join(encoded)


def canonical_candidate_id(
    run_id,
    file_sha256,
    canonical_path,
    archive_sha256=None,
    archive_chain=(),
    member_path=None,
    member_sha256=None,
):
    """Return a stable, collision-resistant ID for a scan candidate."""
    chain = tuple(_normalized_path(item) for item in (archive_chain or ()))
    parts = (
        "candidate-v1",
        run_id,
        file_sha256,
        _normalized_path(canonical_path),
        archive_sha256 or "",
        *chain,
        _normalized_path(member_path) if member_path is not None else "",
        member_sha256 or "",
    )
    return hashlib.sha256(_length_delimited(parts)).hexdigest()


def fuse_behavioral_scores(scores, ratio, cap):
    """Fuse positive correlated behavioral scores with corroboration and cap."""
    if not 0 <= ratio <= 1:
        raise ValueError("ratio must be between 0 and 1")
    cap = int(cap)
    if cap < 0:
        raise ValueError("cap must be non-negative")

    positive = []
    for score in scores.values():
        score = int(score)
        if score > 0:
            positive.append(score)
    if not positive:
        return 0

    primary = max(positive)
    secondary = sum(positive) - primary
    fused = primary + math.floor(secondary * ratio)
    return min(fused, cap)


def decision_reason(
    evidence_groups,
    total_score,
    min_score,
    gray_min,
    yara_timeout=False,
    coverage="full",
):
    """Return a stable reason code for the evidence/threshold state."""
    groups = set(evidence_groups or ())
    if yara_timeout:
        return "manual_review_yara_timeout"
    if coverage != "full":
        return "coverage_partial"
    if groups == {"entropy"}:
        return "entropy_only"
    if groups == {"filename_ioc"}:
        return "filename_only"
    if groups == {"ssdeep"}:
        return "fuzzy_hash_only"
    if len(groups) == 1 and groups & _BEHAVIORAL_DETECTORS:
        return "behavioral_single_evidence"
    if int(total_score) < int(min_score) or int(total_score) < int(gray_min):
        return "below_report_threshold"
    return "report_threshold_met"
