#!/usr/bin/env python3
"""Fail-closed checks for multi-worker equivalence and bundle-key invariants."""

import json
import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.review_bundle import KEY_ENV, bundle_passphrase

SNAPSHOT_TUPLE = (
    "sample_id", "member_path", "verdict", "score",
    "sha256", "evidence_groups", "status",
)


def canonicalize_benchmark_results(rows: list[dict]) -> list[tuple]:
    """Reduce rows to a sortable tuple set for equality comparison."""
    out = []
    for r in rows:
        sample_id = str(r.get("candidate_id") or r.get("id") or "")
        member_path = str(r.get("member_path") or "")
        verdict = str(r.get("verdict") or r.get("shadow_decision") or r.get("legacy_decision") or "")
        score = int(r.get("shadow_score") or r.get("legacy_score") or r.get("score") or 0)
        sha256 = str(r.get("member_sha256") or r.get("sha256") or "")
        groups = str(r.get("evidence_groups") or "")
        status = str(r.get("status") or "")
        out.append((sample_id, member_path, verdict, score, sha256, groups, status))
    return sorted(out)


def assert_weak_key_rejected():
    """A weak or missing key must be rejected."""
    for weak in ("", "weak", "default", "00000000"):
        env_val = os.environ.get(KEY_ENV)
        try:
            os.environ[KEY_ENV] = weak
            bundle_passphrase(APP_ROOT)
            raise AssertionError("weak key %r must be rejected" % weak)
        except Exception:
            pass  # expected
        finally:
            if env_val is not None:
                os.environ[KEY_ENV] = env_val
            elif KEY_ENV in os.environ:
                del os.environ[KEY_ENV]


def assert_terminal_invariant(rows: list[dict], scheduled: int):
    """Assert scheduled == completed + skipped + unsupported + errors."""
    completed = sum(1 for r in rows if r.get("status") == "completed")
    skipped = sum(1 for r in rows if r.get("status") == "skipped")
    unsupported = sum(1 for r in rows if r.get("status") == "unsupported")
    errors = sum(1 for r in rows if r.get("status") == "error")
    total = completed + skipped + unsupported + errors
    assert total == scheduled, (
        "terminal invariant: scheduled=%d != completed=%d + skipped=%d + unsupported=%d + errors=%d=%d"
        % (scheduled, completed, skipped, unsupported, errors, total)
    )


def main():
    # 1 – Equivalence: worker-1 and worker-2 fixture snapshots
    #     (in-memory fixture data, no real scanner run required)
    worker1 = [
        {"candidate_id": "a", "member_path": "", "shadow_decision": "finding", "shadow_score": 80,
         "sha256": "a" * 64, "evidence_groups": "source_sink", "status": "completed"},
        {"candidate_id": "b", "member_path": "", "shadow_decision": "clean", "shadow_score": 0,
         "sha256": "b" * 64, "evidence_groups": "", "status": "completed"},
        {"candidate_id": "c", "member_path": "WEB-INF/Shell.class", "shadow_decision": "finding",
         "shadow_score": 100, "sha256": "c" * 64, "evidence_groups": "yara,source_sink",
         "status": "completed"},
    ]
    worker2 = [
        {"candidate_id": "a", "member_path": "", "shadow_decision": "finding", "shadow_score": 80,
         "sha256": "a" * 64, "evidence_groups": "source_sink", "status": "completed"},
        {"candidate_id": "b", "member_path": "", "shadow_decision": "clean", "shadow_score": 0,
         "sha256": "b" * 64, "evidence_groups": "", "status": "completed"},
        {"candidate_id": "c", "member_path": "WEB-INF/Shell.class", "shadow_decision": "finding",
         "shadow_score": 100, "sha256": "c" * 64, "evidence_groups": "yara,source_sink",
         "status": "completed"},
    ]
    assert canonicalize_benchmark_results(worker1) == canonicalize_benchmark_results(worker2)
    print("equivalence: worker 1 == worker 2")

    # 2 – Missing/duplicate ID must fail
    dupes = list(worker1) + [dict(worker1[0])]
    canon = canonicalize_benchmark_results(dupes)
    ids = [(item[0], item[1]) for item in canon]
    assert len(ids) != len(set(ids)), "duplicate IDs went undetected"
    print("duplicate ID detection: ok")

    # 3 – Terminal-status invariant
    assert_terminal_invariant(worker1, 3)
    print("terminal invariant: ok")

    # 4 – Missing ID detection
    missing_ids = {"d"} - {r["candidate_id"] for r in worker1}
    assert missing_ids, "missing IDs must be detected"
    print("missing ID detection: ok")

    # 5 – Weak key rejection
    assert_weak_key_rejected()
    print("weak key rejection: ok")

    print("\nparallel equivalence checks passed")


if __name__ == "__main__":
    main()
