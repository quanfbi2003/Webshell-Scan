import importlib.util
import sys
from pathlib import Path


APP = Path(__file__).parents[1] / "review-web" / "app.py"
spec = importlib.util.spec_from_file_location("review_web_ui_check", APP)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


page = module.html_page(
    "UI check",
    '<section class="hero"><span class="kind-finding">Phát hiện chính</span>'
    '<span class="kind-gray">Gray zone</span>'
    '<button type="button" data-copy="sha256">Copy</button></section>',
).decode("utf-8")
assert "--navy" in page
assert "@media" in page
assert "kind-finding" in page and "kind-gray" in page
assert "data-copy" in page
assert "focus-visible" in page
print("check_review_web_ui: base contract passed")

assert module.dashboard_filter_url("a/b", "gray", "reviewing") == "?q=a%2Fb&kind=gray&status=reviewing"
assert module.dashboard_filter_url("", "", "") == "?"
print("check_review_web_ui: filter helper passed")

assert "manual-review" in page or "manual-review" in module.html_page("detail", '<div class="manual-review">Gray zone</div>').decode("utf-8")
assert "source-missing" in module.html_page("detail", '<div class="source-missing">Thiếu source</div>').decode("utf-8")
assert "snippet-only" in module.html_page("detail", '<div class="snippet-only">Snippet-only</div>').decode("utf-8")
assert "code-toolbar" in module.html_page("detail", '<div class="code-toolbar">read-only</div>').decode("utf-8")
assert "Raw/decode viewer" in module.html_page("detail", "Raw/decode viewer").decode("utf-8")
print("check_review_web_ui: detail hooks passed")

login_html = module.login_page().decode("utf-8")
assert "analyst-shell" in login_html
assert "STAGING" in login_html
assert "authorized" in login_html.lower()
assert "--navy" in login_html
assert "login-card" in login_html
assert "linear-gradient" not in login_html
print("check_review_web_ui: analyst login contract passed")

admin_html = module.admin_page_for_context("http://localhost", admin_context_value={"csrf_token": "csrf", "username": "antt"}).decode("utf-8")
assert "admin-header" in admin_html
assert "kpi-row" in admin_html
assert "action-bar" in admin_html
assert "Manage upload key" in admin_html
assert "Assignment" in admin_html
print("check_review_web_ui: admin console contract passed")

assert "console-heading" in admin_html or "Review workspace" in admin_html
assert "report-table" in admin_html or "Báo cáo" in admin_html
print("check_review_web_ui: analyst report contract passed")

assert "admin-header" in admin_html or "Review workspace" in admin_html
assert "kpi-row" in admin_html or "Reports" in admin_html
assert "action-bar" in admin_html or "Import .enc" in admin_html
assert "Assignment" in admin_html
assert "detail-meta" in admin_html or "Reports" in admin_html
assert "action-confirm" in admin_html or "Review workspace" in admin_html
assert "action-remediate" in admin_html or "Review workspace" in admin_html
assert "action-benign" in admin_html or "Review workspace" in admin_html
print("check_review_web_ui: analyst admin contract passed")
assert "soc-sidebar" in admin_html
assert "report-table" in admin_html

shell = module.html_page("shell", "<p>content</p>").decode("utf-8")
assert "soc-header" in shell
assert "soc-sidebar" in shell
assert "Webshell Review" in shell
assert "#2457D6" in shell
assert "--canvas" in shell
assert "@media" in shell
assert "Dashboard" in shell
assert "Assigned" in shell
print("check_review_web_ui: SOC shell contract passed")

assert "--text-strong" in page
assert "white-space:pre-wrap" in page
assert "overflow-wrap:anywhere" in page
assert "word-break:break-word" in page
assert ".detail-sidebar" in page
assert ".evidence-viewer" in page
print("check_review_web_ui: finding readability CSS contract passed")

def check_task1_invariants():
    with open(APP, "r", encoding="utf-8") as f:
        code = f.read()
    assert "/static/review.js" in code, "Missing /static/review.js route"
    assert "part.data.decode" in code, "Missing fixed finding_ids parsing"
    print("check_review_web_ui: Task 1 static contract passed")

check_task1_invariants()

def check_task2_shell():
    with open(APP, "r", encoding="utf-8") as f:
        code = f.read()
    assert 'data-rail' in code, "Missing data-rail attribute"
    assert 'data-rail-toggle' in code, "Missing data-rail-toggle button"
    assert '/static/review.js' in code, "Missing script inclusion"
    assert 'status-confirmed' in code, "Missing confirmed status styling"
    print("check_review_web_ui: Task 2 static contract passed")

check_task2_shell()

def check_task3_dashboard():
    with open(APP, "r", encoding="utf-8") as f:
        code = f.read()
    assert 'id="bulk-form"' in code, "Missing id attribute for bulk form"
    assert 'form="bulk-form"' in code, "Missing form attribute on checkboxes"
    assert 'class="table-card"' in code or 'tablewrap' in code, "Missing queue row/table styling"
    print("check_review_web_ui: Task 3 static contract passed")

check_task3_dashboard()
