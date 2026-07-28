from libs.evidence import canonical_candidate_id, fuse_behavioral_scores, make_evidence


assert make_evidence("source_sink", 55, "hit")["detector"] == "source_sink"
assert make_evidence("ast_df", status="model_incompatible")["status"] == "model_incompatible"
assert canonical_candidate_id("run-1", "a" * 64, "/tmp/a") != canonical_candidate_id("run-2", "a" * 64, "/tmp/a")
assert canonical_candidate_id(
    "run", "a" * 64, "/tmp/a", "b" * 64, ("outer.war",),
    "WEB-INF/Shell.class", "c" * 64,
)
assert fuse_behavioral_scores(
    {"source_sink": 55, "behavior_graph": 72, "ast_df": 80}, 0.25, 100
) == 100
try:
    fuse_behavioral_scores({"source_sink": 1}, 1.1, 100)
except ValueError:
    pass
else:
    raise AssertionError("ratio outside [0, 1] must fail")
print("evidence checks passed")
