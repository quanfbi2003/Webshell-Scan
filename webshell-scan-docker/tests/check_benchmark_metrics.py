"""Small metric accounting checks for the benchmark helpers."""

from libs.benchmark import compute_metrics, threshold_sweep


def main():
    results = [
        {"id": "tp", "label": "webshell", "status": "detected", "predicted": "webshell", "score": 90},
        {"id": "fp", "label": "benign", "status": "detected", "predicted": "webshell", "score": 80},
        {"id": "tn", "label": "benign", "status": "clean", "predicted": "benign", "score": 0},
        {"id": "fn", "label": "webshell", "status": "clean", "predicted": "benign", "score": 10},
        {"id": "error", "label": "benign", "status": "error", "predicted": None, "score": None},
    ]
    metrics = compute_metrics(results)
    assert metrics["TP"] == 1
    assert metrics["FP"] == 1
    assert metrics["TN"] == 1
    assert metrics["FN"] == 1
    assert metrics["coverage"] == 4 / 5
    assert metrics["unknown_rate"] == 1 / 5
    assert metrics["gray_zone"] == 0

    for status in ("error", "skipped", "unsupported"):
        row = dict(results[2], id=status, status=status, predicted="benign")
        checked = compute_metrics(results[:4] + [row])
        assert checked["TN"] == 1
        assert checked["unknown_rate"] == 1 / 5

    locked = [dict(row) for row in results]
    before = [dict(row) for row in locked]
    sweep = threshold_sweep(locked, [0, 50, 85])
    assert [row["threshold"] for row in sweep] == [0, 50, 85]
    assert locked == before
    assert all("TP" in row and "unknown_rate" in row for row in sweep)
    print("benchmark metrics checks passed")


if __name__ == "__main__":
    main()
