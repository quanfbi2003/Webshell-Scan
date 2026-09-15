import importlib.util
import os
import sys
import tempfile
from pathlib import Path

APP = Path(__file__).parents[1] / "review-web" / "app.py"
spec = importlib.util.spec_from_file_location("review_web_auth_check", APP)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
    module.DATA_DIR = Path(tmp)
    module.DB_PATH = module.DATA_DIR / "review.db"
    module.CONFIG_PATH = module.DATA_DIR / "config.json"
    os.environ["REVIEW_BOOTSTRAP_PASSWORD"] = "Vnpt@123"
    module.ensure_dirs()
    with module.sqlite3.connect(module.DB_PATH) as legacy_conn:
        legacy_conn.execute(
            "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, finding_id INTEGER, action TEXT NOT NULL, detail TEXT, created_at INTEGER NOT NULL)"
        )
    encoded = module.hash_password("Correct horse battery")

    # Existing databases must accept audit entries without a case scope.
    module.init_db()
    with module.connect_db() as conn:
        audit_columns = {row["name"]: row for row in conn.execute("PRAGMA table_info(audit_log)")}
        assert audit_columns["case_id"]["notnull"] == 0

    # The remainder of this check exercises the migrated schema.

    assert encoded.startswith("scrypt$v1$")
    assert module.verify_password("Correct horse battery", encoded)
    assert not module.verify_password("wrong", encoded)
    assert not module.verify_password("Correct horse battery", "scrypt$v0$bad")
    assert module.normalize_username("  Alice.Admin ") == "alice.admin"
    module.init_db()
    with module.connect_db() as conn:
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"users", "user_sessions", "case_assignments", "upload_credentials"} <= tables
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(cases)")}
        assert {"uploaded_by_user_id", "upload_origin"} <= columns
    with module.connect_db() as conn:
        admin_id = conn.execute("SELECT id FROM users WHERE username='antt'").fetchone()["id"]
    user_id = module.create_customer_user("Alice", "long secure password", admin_id)
    with module.connect_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        assert row["role"] == "user"
        assert module.verify_password("long secure password", row["password_hash"])
    try:
        module.create_customer_user("alice", "another long password", admin_id)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate normalized username accepted")
    token, _ = module.create_user_session(user_id)
    module.set_user_active(user_id, False, admin_id)
    assert not module.query_one("SELECT 1 FROM user_sessions WHERE token=?", (token,))
    module.set_user_active(user_id, True, admin_id)
    module.reset_user_password(user_id, "new secure password", admin_id)
    assert module.verify_password("new secure password", module.query_one("SELECT password_hash FROM users WHERE id=?", (user_id,))["password_hash"])
    with module.connect_db() as conn:
        case_a = conn.execute("INSERT INTO cases(title,share_key,created_at,upload_origin) VALUES(?,?,?,?)", ("case-a", "share-a", 1, "remote_upload")).lastrowid
        case_b = conn.execute("INSERT INTO cases(title,share_key,created_at,upload_origin) VALUES(?,?,?,?)", ("case-b", "share-b", 1, "remote_upload")).lastrowid
    module.assign_report(case_a, user_id, admin_id)
    assert module.case_visible_to_user(case_a, user_id)
    assert not module.case_visible_to_user(case_b, user_id)
    module.revoke_report(case_a, user_id, admin_id)
    assert not module.case_visible_to_user(case_a, user_id)
    module.assign_report(case_a, user_id, admin_id)
    with module.connect_db() as conn:
        finding_id = conn.execute("INSERT INTO findings(case_id,file_path,status,created_at) VALUES(?,?,?,?)", (case_a, "a.php", "pending", 1)).lastrowid
        other_id = conn.execute("INSERT INTO findings(case_id,file_path,status,created_at) VALUES(?,?,?,?)", (case_b, "b.php", "pending", 1)).lastrowid
    context = {"role": "user", "user_id": user_id, "csrf_token": "csrf"}
    dashboard_html = module.case_dashboard(case_a, {}, context).decode("utf-8")
    assert 'name="csrf_token" value="csrf"' in dashboard_html or 'name=\'csrf_token\' value=\'csrf\'' in dashboard_html
    detail_html = module._render_finding_detail(case_a, finding_id, {}, role="reviewer", context=context).decode("utf-8")
    assert 'name="csrf_token"' in detail_html
    assert "detail-meta" in detail_html
    assert "detail-sidebar" in detail_html
    assert "evidence-viewer" in detail_html
    assert "Copy SHA256" in detail_html
    assert 'type="button" class="action-confirm"' in detail_html
    try:
        module.update_finding_status(case_a, finding_id, "benign", "   ", context)
    except ValueError:
        pass
    else:
        raise AssertionError("empty benign note accepted")
    module.update_finding_status(case_a, finding_id, "benign", "reviewed", context)
    try:
        module.bulk_update_findings(case_a, [finding_id, other_id], "confirmed", "", context)
    except ValueError:
        pass
    else:
        raise AssertionError("cross-case bulk selection accepted")
    assert module.bulk_update_findings(case_a, [finding_id], "remediated", "", context) == 1

    admin_token, _ = module.create_admin_session(admin_id)
    user_token, _ = module.create_user_session(user_id)
    legacy_token = module.create_session(case_a, "reviewer")
    module.revoke_sessions({"Cookie": f"review_admin={admin_token}; review_user={user_token}; review_session={legacy_token}"})
    with module.connect_db() as conn:
        assert not conn.execute("SELECT 1 FROM admin_sessions WHERE token=?", (admin_token,)).fetchone()
        assert not conn.execute("SELECT 1 FROM user_sessions WHERE token=?", (user_token,)).fetchone()
        assert not conn.execute("SELECT 1 FROM sessions WHERE token=?", (legacy_token,)).fetchone()
print("check_review_web_auth: password/schema/lifecycle/assignment/bulk/logout passed")
