"""Fail-closed benchmark manifest loading and metric accounting."""

import hashlib
import json
import os


_LABELS = {"webshell", "benign"}
_COMPLETED = {"detected", "clean"}
_REQUIRED = {"id", "path", "label", "language", "sha256", "family"}
_ARCHIVE_REQUIRED = {"member_path", "member_sha256"}


def _resolve(root, path):
    root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root, path))
    if os.path.commonpath((root, candidate)) != root:
        raise ValueError("case path escapes root: %s" % path)
    return candidate


def validate_case(case, root):
    if not isinstance(case, dict):
        raise ValueError("case must be an object")
    missing = _REQUIRED - set(case)
    if missing:
        raise ValueError("missing required fields: %s" % ", ".join(sorted(missing)))
    if not isinstance(case["id"], str) or not case["id"]:
        raise ValueError("id must be a non-empty string")
    if case["label"] not in _LABELS:
        raise ValueError("invalid label: %s" % case["label"])
    digest = case["sha256"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("sha256 must be a 64-character hexadecimal digest")
    try:
        int(digest, 16)
    except ValueError:
        raise ValueError("sha256 must be hexadecimal")
    archive = case.get("archive", False)
    if not isinstance(archive, bool):
        raise ValueError("archive must be boolean")
    if archive and not _ARCHIVE_REQUIRED.issubset(case):
        raise ValueError("archive cases require member_path and member_sha256")
    path = _resolve(root, case["path"])
    if not os.path.isfile(path):
        raise ValueError("case file does not exist: %s" % case["path"])
    with open(path, "rb") as handle:
        actual = hashlib.sha256(handle.read()).hexdigest()
    if actual != digest.lower():
        raise ValueError("sha256 mismatch for %s" % case["id"])
    if archive:
        member_digest = case["member_sha256"]
        if not isinstance(member_digest, str) or len(member_digest) != 64:
            raise ValueError("member_sha256 must be a 64-character hexadecimal digest")
        try:
            int(member_digest, 16)
        except ValueError:
            raise ValueError("member_sha256 must be hexadecimal")
    return None


def load_cases(path, root):
    cases = []
    seen = set()
    with open(path, encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON on line %d" % line_number) from exc
            case_id = case.get("id") if isinstance(case, dict) else None
            if case_id in seen:
                raise ValueError("duplicate case id: %s" % case_id)
            validate_case(case, root)
            seen.add(case_id)
            cases.append(case)
    return cases


def record_result(case, status, predicted, score, **metadata):
    result = {
        "id": case["id"],
        "label": case["label"],
        "status": status,
        "predicted": predicted,
        "score": score,
    }
    result.update(metadata)
    return result


def _outcome(row, threshold=None):
    status = row.get("status")
    if status not in _COMPLETED:
        return None
    predicted = row.get("predicted")
    if threshold is not None and row.get("score") is not None:
        predicted = "webshell" if row["score"] >= threshold else "benign"
    if predicted not in _LABELS:
        return None
    return (row.get("label"), predicted)


def compute_metrics(results, threshold=None):
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    gray_zone = 0
    for row in results:
        outcome = _outcome(row, threshold)
        if outcome is None:
            if row.get("status") == "gray_zone":
                gray_zone += 1
            continue
        label, predicted = outcome
        if label == "webshell" and predicted == "webshell":
            counts["TP"] += 1
        elif label == "benign" and predicted == "webshell":
            counts["FP"] += 1
        elif label == "benign" and predicted == "benign":
            counts["TN"] += 1
        elif label == "webshell" and predicted == "benign":
            counts["FN"] += 1
    completed = sum(counts.values())
    total = len(results)
    counts["coverage"] = completed / total if total else 0.0
    counts["unknown_rate"] = (total - completed) / total if total else 0.0
    counts["gray_zone"] = gray_zone
    return counts


def threshold_sweep(results, thresholds):
    return [dict(compute_metrics(results, threshold=threshold), threshold=threshold) for threshold in thresholds]


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
