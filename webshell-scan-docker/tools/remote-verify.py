#!/usr/bin/env python3
"""SSH helper for Task 10 remote verification."""

import getpass
import json
import os
import subprocess
import sys
import tarfile
import tempfile

import paramiko

HOST = "10.144.8.234"
USER = "antt"
PASSWORD = "Vnpt@1234"
REMOTE_DIR = "/home/antt/webshell-test-run"


def ssh_client():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=15)
    return client


def run(client, command, sudo=False):
    if sudo:
        command = "sudo " + command
    stdin, stdout, stderr = client.exec_command(command, timeout=60, get_pty=True)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return exit_code, out, err


def run_ok(client, command, label=""):
    code, out, err = run(client, command)
    ok = "OK" if code == 0 else "FAIL"
    print("  [%s] %s" % (ok, label or command))
    if code != 0:
        print("    exit=%d out=%s err=%s" % (code, out.strip(), err.strip()))
    return code, out, err


def main():
    if "--step1" in sys.argv:
        return step1()
    elif "--step2" in sys.argv:
        return step2()
    elif "--step3" in sys.argv:
        return step3()
    elif "--step4" in sys.argv:
        return step4()
    elif "--step5" in sys.argv:
        return step5()
    elif "--step6" in sys.argv:
        return step6()
    elif "--step7" in sys.argv:
        return step7()
    print("Usage: --step1|2|3|4|5|6|7")
    sys.exit(1)


# ── Step 1: Verify remote host + isolated target ──

def step1():
    client = ssh_client()
    print("=== Step 1: Verify remote host ===")
    run_ok(client, "hostname")
    run_ok(client, "id -un")
    run_ok(client, "python3 --version")
    run_ok(client, "git --version")
    code, out, _ = run(client, "pwd")
    run_ok(client, 'ls -d %s 2>/dev/null && echo "EXISTS" || echo "NOT_EXISTS"' % REMOTE_DIR,
           "Check %s" % REMOTE_DIR)
    run_ok(client, 'ls -d /home/antt/webshell-test 2>/dev/null && echo "EXISTS" || echo "NOT_EXISTS"',
           "Check /home/antt/webshell-test")
    run_ok(client, 'test "%s" != "/home/antt/webshell-test" && echo "ISOLATED" || echo "NOT_ISOLATED"' % REMOTE_DIR,
           "Isolation check")
    print("\nStep 1: host verified")
    client.close()
    return 0


# ── Step 2: Upload source snapshot ──

def step2():
    """Create git archive from current HEAD and upload."""
    import hashlib

    APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(APP_ROOT)

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    print("=== Step 2: Upload source snapshot (commit %s) ===" % commit)

    # Create git archive
    archive_path = tempfile.mktemp(suffix=".tar.gz")
    try:
        subprocess.check_call(
            ["git", "archive", "--format=tar.gz", "-o", archive_path, "HEAD"],
            cwd=APP_ROOT, timeout=30,
        )
        with open(archive_path, "rb") as f:
            archive_data = f.read()
        sha256 = hashlib.sha256(archive_data).hexdigest()
        print("Archive SHA256: %s, size: %d bytes" % (sha256, len(archive_data)))

        # SFTP upload
        client = ssh_client()
        sftp = client.open_sftp()
        try:
            sftp.stat(REMOTE_DIR)
        except FileNotFoundError:
            sftp.mkdir(REMOTE_DIR)
        dest = "%s/source.tar.gz" % REMOTE_DIR
        with sftp.open(dest, "wb") as f:
            f.write(archive_data)
        sftp.close()

        # Extract on remote
        run_ok(client, "cd %s && tar xzf source.tar.gz && rm source.tar.gz && ls -la" % REMOTE_DIR, "Extract archive")
        # Verify commit hash on remote
        run_ok(client, "cd %s && git log -1 --format=%%H" % REMOTE_DIR, "Verify commit on remote")

        client.close()
        print("Step 2: upload complete")
    finally:
        os.unlink(archive_path)
    return 0


# ── Step 3: Inventory dependencies ──

def step3():
    client = ssh_client()
    print("=== Step 3: Remote dependency inventory ===")
    MODULES = ("yara", "cryptography", "ssdeep", "numpy", "sklearn", "deepforest")
    for name in MODULES:
        code, out, _ = run(client, "python3 -c 'import %s; print(\"present\")' 2>/dev/null || echo missing" % name)
        status = out.strip()
        print("  %s = %s" % (name, status))
    client.close()
    return 0


# ── Step 4: Remote compile + all checks ──

def step4():
    client = ssh_client()
    print("=== Step 4: Remote syntax and focused checks ===")

    # Compile
    compiles = [
        "webshell-scan.py", "libs/evidence.py", "libs/benchmark.py",
        "libs/scan_policy.py", "libs/ast_df.py", "libs/review_bundle.py",
        "tools/run-benchmark.py",
    ]
    cmd = "cd %s && python3 -m py_compile " % REMOTE_DIR + " ".join(compiles)
    run_ok(client, cmd, "Compile all")

    # All checks
    CHECKS = [
        "check_evidence.py", "check_benchmark_manifest.py", "check_benchmark_metrics.py",
        "check_policy_validation.py", "check_model_metadata.py", "check_scanner_evidence.py",
        "check_report_schema.py", "check_review_bundle_compat.py", "check_archive_benchmark.py",
        "check_parallel_equivalence.py", "check_ast_df.py", "check_fp_guard.py",
        "check_scan_policy_defaults.py",
    ]
    results = {}
    for check in CHECKS:
        code, out, err = run(
            client, "cd %s && PYTHONPATH=. python3 tests/%s" % (REMOTE_DIR, check),
        )
        ok = code == 0 and ("passed" in out.lower() or "ok" in out.lower() or "aligned" in out.lower())
        results[check] = (code, ok)
        print("  [%s] %s" % ("PASS" if ok else "FAIL", check))
        if not ok:
            print("    out: %s" % out.strip()[-200:])

    # Regression
    code, out, _ = run(client, "cd %s && PYTHONPATH=. python3 tests/run-regression.py" % REMOTE_DIR)
    reg_ok = code == 0 and "PASS" in out
    results["regression"] = (code, reg_ok)
    print("  [%s] run-regression.py" % ("PASS" if reg_ok else "FAIL"))

    failed = [k for k, (_, ok) in results.items() if not ok]
    if failed:
        print("\nFAILED: %s" % ", ".join(failed))
    else:
        print("\nAll checks PASS")
    client.close()
    return 1 if failed else 0


# ── Step 5: Remote shadow benchmark ──

def step5():
    client = ssh_client()
    print("=== Step 5: Remote shadow benchmark ===")
    run_ok(client, "mkdir -p /tmp/webshell-quality-run")
    cmd = ("cd %s && PYTHONPATH=. python3 tools/run-benchmark.py"
           " --manifest tests/fixtures/benchmark/cases.jsonl"
           " --root . --workers 1 --shadow-only"
           " --output /tmp/webshell-quality-run/benchmark-ubuntu.json") % REMOTE_DIR
    code, out, err = run(client, cmd, "Shadow benchmark (workers=1)")
    print(out.strip())
    if code != 0:
        print("STDERR: %s" % err.strip())
    client.close()
    return code


# ── Step 6: Remote worker equivalence ──

def step6():
    client = ssh_client()
    print("=== Step 6: Remote worker equivalence ===")
    cmd2 = ("cd %s && PYTHONPATH=. python3 tools/run-benchmark.py"
            " --manifest tests/fixtures/benchmark/cases.jsonl"
            " --root . --workers 2 --shadow-only"
            " --output /tmp/webshell-quality-run/benchmark-ubuntu-workers-2.json") % REMOTE_DIR
    run_ok(client, cmd2, "Shadow benchmark (workers=2)")

    cmd_eq = ("cd %s && python3 -c \""
              "import sys; sys.path.insert(0, '.');"
              "from tests.check_parallel_equivalence import canonicalize_benchmark_results;"
              "import json;"
              "w1 = json.load(open('/tmp/webshell-quality-run/benchmark-ubuntu.json')).get('results', json.load(open('/tmp/webshell-quality-run/benchmark-ubuntu.json')).get('records', []));"
              "w2 = json.load(open('/tmp/webshell-quality-run/benchmark-ubuntu-workers-2.json')).get('results', json.load(open('/tmp/webshell-quality-run/benchmark-ubuntu-workers-2.json')).get('records', []));"
              "c1 = canonicalize_benchmark_results(w1); c2 = canonicalize_benchmark_results(w2);"
              "assert c1 == c2, 'worker 1 and 2 results differ: %%s vs %%s' %% (len(c1), len(c2));"
              "print('equivalence: worker 1 == worker 2, IDs: %%d' %% len(c1));"
              "\"") % REMOTE_DIR
    run_ok(client, cmd_eq, "Worker equivalence check")
    client.close()
    return 0


# ── Step 7: Collect results ──

def step7():
    client = ssh_client()
    print("=== Step 7: Collect remote results ===")
    sftp = client.open_sftp()
    local_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    os.makedirs(local_dir, exist_ok=True)

    for name in ("benchmark-ubuntu.json", "benchmark-ubuntu-workers-2.json"):
        remote = "/tmp/webshell-quality-run/%s" % name
        local = os.path.join(local_dir, name)
        try:
            sftp.stat(remote)
            sftp.get(remote, local)
            size = os.path.getsize(local)
            print("  Collected %s (%d bytes)" % (local, size))
        except FileNotFoundError:
            print("  WARNING: %s not found on remote" % remote)
    sftp.close()
    client.close()
    print("Step 7: collection complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
