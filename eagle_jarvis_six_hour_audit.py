#!/usr/bin/env python3
"""
EAGLE JARVIS six-hour repeat audit.
Read-only: does not edit/delete project source files or install packages.
Scans the project folder containing this script, repeating checks every 10 minutes
for up to 6 hours. Errors in one check are recorded and other checks continue.
"""
from __future__ import annotations

import ast
import datetime as dt
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

DURATION_SECONDS = 6 * 60 * 60
INTERVAL_SECONDS = 10 * 60
SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".idea", ".vscode", "dist", "build", "reports"
}
TEXT_SUFFIXES = {
    ".py", ".html", ".htm", ".js", ".mjs", ".cjs", ".css",
    ".json", ".toml", ".ini", ".cfg", ".md", ".txt", ".yml", ".yaml"
}
SECRET_PATTERNS = [
    ("possible credential assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})"
    )),
    ("Google API key pattern", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
]
LOCAL_URL_RE = re.compile(r"https?://(?:127\.0\.0\.1|localhost):(\d+)", re.I)
SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "credentials.json", "service-account.json"
}


def timestamp():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def stamp():
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def discover_files(root: Path):
    found = []
    for current, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(current) / name
            if path.suffix.lower() in TEXT_SUFFIXES:
                found.append(path)
    return found


def relative(path: Path, root: Path):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def check_python(path: Path, root: Path, findings: list, stats: dict):
    rel = relative(path, root)
    try:
        # utf-8-sig accepts a leading BOM, so this checks actual Python syntax.
        source = path.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(source, filename=rel)
        stats["python_files_parsed"] += 1
    except SyntaxError as exc:
        findings.append({
            "severity": "HIGH", "category": "Python syntax",
            "file": rel, "line": exc.lineno or 0,
            "message": f"Syntax error: {exc.msg}"
        })
        stats["python_syntax_errors"] += 1
        return
    except Exception as exc:
        stats["errors"].append({
            "check": "python_syntax", "file": rel,
            "error": f"{type(exc).__name__}: {str(exc)[:250]}"
        })
        return

    try:
        definitions = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                definitions.setdefault((type(node).__name__, node.name), []).append(node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    findings.append({
                        "severity": "HIGH", "category": "Risky Python pattern",
                        "file": rel, "line": getattr(node, "lineno", 0),
                        "message": "eval() call found; review whether untrusted input can reach it."
                    })
                elif node.func.id == "exec":
                    findings.append({
                        "severity": "MEDIUM", "category": "Risky Python pattern",
                        "file": rel, "line": getattr(node, "lineno", 0),
                        "message": "exec() call found; review carefully."
                    })
        for (kind, name), lines in definitions.items():
            if len(lines) > 1:
                findings.append({
                    "severity": "MEDIUM", "category": "Duplicate definition",
                    "file": rel, "line": lines[-1],
                    "message": f"{kind} '{name}' is defined multiple times at lines {', '.join(map(str, lines))}."
                })
    except Exception as exc:
        stats["errors"].append({
            "check": "python_patterns", "file": rel,
            "error": f"{type(exc).__name__}: {str(exc)[:250]}"
        })


def check_text(path: Path, root: Path, findings: list, stats: dict):
    rel = relative(path, root)
    if path.name.lower() in SENSITIVE_NAMES:
        stats["sensitive_files_skipped"] += 1
        return
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        stats["errors"].append({
            "check": "text_read", "file": rel,
            "error": f"{type(exc).__name__}: {str(exc)[:250]}"
        })
        return

    stats["text_files_scanned"] += 1
    try:
        for line_no, line in enumerate(content.splitlines(), 1):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "severity": "HIGH", "category": "Possible exposed secret",
                        "file": rel, "line": line_no,
                        "message": f"{label} pattern detected; matched value and source line intentionally omitted."
                    })
                    break
        if path.name.lower() == "index.html":
            ports = sorted(set(LOCAL_URL_RE.findall(content)))
            if ports:
                stats["dashboard_localhost_ports"][rel] = ports
            if "fetch(" not in content and "XMLHttpRequest" not in content:
                findings.append({
                    "severity": "INFO", "category": "Frontend review",
                    "file": rel, "line": 0,
                    "message": "No fetch() or XMLHttpRequest string found; manually verify dashboard API calls."
                })
    except Exception as exc:
        stats["errors"].append({
            "check": "text_patterns", "file": rel,
            "error": f"{type(exc).__name__}: {str(exc)[:250]}"
        })


def check_backend_health(stats: dict, findings: list):
    # Only makes a local GET request; does not restart the server or send commands to Gemini.
    url = "http://127.0.0.1:8010/api/health"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "EAGLE-JARVIS-local-audit"})
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            stats["backend_health"] = {
                "url": url, "http_status": response.status, "response": body[:1000]
            }
            if response.status != 200:
                findings.append({
                    "severity": "MEDIUM", "category": "Backend health",
                    "file": "local endpoint", "line": 0,
                    "message": f"Health endpoint returned HTTP {response.status}."
                })
    except urllib.error.HTTPError as exc:
        stats["backend_health"] = {"url": url, "error": f"HTTP {exc.code}"}
        findings.append({
            "severity": "MEDIUM", "category": "Backend health",
            "file": "local endpoint", "line": 0,
            "message": f"Health endpoint returned HTTP {exc.code}."
        })
    except Exception as exc:
        stats["backend_health"] = {"url": url, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        findings.append({
            "severity": "INFO", "category": "Backend health",
            "file": "local endpoint", "line": 0,
            "message": "Local health endpoint did not respond. This may simply mean the backend is not running."
        })


def run_round(root: Path, round_number: int):
    started = time.monotonic()
    stats = {
        "round": round_number,
        "started_at": timestamp(),
        "files_discovered": 0,
        "python_files_parsed": 0,
        "python_syntax_errors": 0,
        "text_files_scanned": 0,
        "sensitive_files_skipped": 0,
        "dashboard_localhost_ports": {},
        "errors": [],
        "backend_health": {},
    }
    findings = []
    try:
        files = discover_files(root)
        stats["files_discovered"] = len(files)
    except Exception as exc:
        files = []
        stats["errors"].append({
            "check": "file_discovery", "file": ".",
            "error": f"{type(exc).__name__}: {str(exc)[:250]}"
        })

    for path in files:
        # Each file/check is isolated: one exception must not stop the whole round.
        if path.suffix.lower() == ".py":
            try:
                check_python(path, root, findings, stats)
            except Exception as exc:
                stats["errors"].append({
                    "check": "python_check", "file": relative(path, root),
                    "error": f"{type(exc).__name__}: {str(exc)[:250]}"
                })
        try:
            check_text(path, root, findings, stats)
        except Exception as exc:
            stats["errors"].append({
                "check": "text_check", "file": relative(path, root),
                "error": f"{type(exc).__name__}: {str(exc)[:250]}"
            })

    try:
        check_backend_health(stats, findings)
    except Exception as exc:
        stats["errors"].append({
            "check": "backend_health", "file": "local endpoint",
            "error": f"{type(exc).__name__}: {str(exc)[:250]}"
        })

    stats["findings_by_severity"] = {}
    for finding in findings:
        severity = finding["severity"]
        stats["findings_by_severity"][severity] = stats["findings_by_severity"].get(severity, 0) + 1
    stats["findings_total"] = len(findings)
    stats["error_count"] = len(stats["errors"])
    stats["duration_seconds"] = round(time.monotonic() - started, 2)
    stats["finished_at"] = timestamp()
    return {"summary": stats, "findings": findings}


def main():
    root = Path(__file__).resolve().parent
    report_dir = root / "reports"
    report_dir.mkdir(exist_ok=True)

    started_wall = timestamp()
    started_mono = time.monotonic()
    deadline = started_mono + DURATION_SECONDS
    rounds = []
    round_number = 0

    print("EAGLE JARVIS SIX-HOUR REPEAT AUDIT")
    print(f"Project: {root}")
    print("Schedule: repeat checks every 10 minutes for up to 6 hours.")
    print("Read-only: no source files changed; .env files are skipped.")
    print("Keep Windows awake and this terminal open. Press Ctrl+C to stop safely.")
    print()

    try:
        while time.monotonic() < deadline:
            round_number += 1
            try:
                result = run_round(root, round_number)
                rounds.append(result)
                s = result["summary"]
                print(
                    f"[{s['finished_at']}] Round {round_number}: "
                    f"{s['files_discovered']} files, {s['findings_total']} findings, "
                    f"{s['error_count']} check errors, {s['duration_seconds']} sec"
                )
            except Exception as exc:
                # Catch unexpected round-level failures and continue at the next interval.
                rounds.append({
                    "summary": {
                        "round": round_number, "started_at": timestamp(),
                        "round_failure": f"{type(exc).__name__}: {str(exc)[:250]}"
                    },
                    "findings": []
                })
                print(f"Round {round_number} failed: {type(exc).__name__}; recorded, will continue.")

            elapsed = time.monotonic() - started_mono
            if elapsed >= DURATION_SECONDS:
                break
            sleep_for = min(INTERVAL_SECONDS, max(0, DURATION_SECONDS - elapsed))
            if sleep_for:
                print(f"Next check in about {int(sleep_for // 60)} minutes.")
                time.sleep(sleep_for)
    except KeyboardInterrupt:
        print("\nStop requested. Saving the results collected so far...")

    finished_wall = timestamp()
    all_findings = []
    all_errors = []
    for item in rounds:
        s = item.get("summary", {})
        all_findings.extend(
            [{"round": s.get("round"), **finding} for finding in item.get("findings", [])]
        )
        all_errors.extend(
            [{"round": s.get("round"), **error} for error in s.get("errors", [])]
        )

    summary = {
        "project_root": str(root),
        "started_at": started_wall,
        "finished_at": finished_wall,
        "elapsed_seconds": round(time.monotonic() - started_mono, 2),
        "scheduled_duration_seconds": DURATION_SECONDS,
        "interval_seconds": INTERVAL_SECONDS,
        "rounds_completed": len(rounds),
        "findings_total_across_rounds": len(all_findings),
        "check_errors_total": len(all_errors),
        "stopped_early_or_interrupted": time.monotonic() - started_mono < DURATION_SECONDS,
        "notes": [
            "This is a local static audit, not a penetration test or guarantee of security.",
            "Backend health checks contact only http://127.0.0.1:8010/api/health; no Gemini command is sent.",
            "Sensitive .env and credential files are skipped; reports omit matching secret values.",
            "The scan does not install packages or modify/delete project source files.",
            "Repeated checks do not guarantee that the scan will discover every possible issue."
        ]
    }
    report = {
        "summary": summary,
        "rounds": rounds,
        "findings_across_rounds": all_findings,
        "check_errors_across_rounds": all_errors,
    }
    file_stamp = stamp()
    json_path = report_dir / f"eagle_jarvis_overnight_{file_stamp}.json"
    text_path = report_dir / f"eagle_jarvis_overnight_{file_stamp}.txt"

    try:
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"Could not write JSON report: {type(exc).__name__}: {str(exc)[:200]}")
    try:
        lines = [
            "EAGLE JARVIS SIX-HOUR REPEAT AUDIT",
            "=" * 38,
            f"Project: {root}",
            f"Started: {summary['started_at']}",
            f"Finished: {summary['finished_at']}",
            f"Elapsed seconds: {summary['elapsed_seconds']}",
            f"Rounds completed: {summary['rounds_completed']}",
            f"Findings across rounds: {summary['findings_total_across_rounds']}",
            f"Check errors across rounds: {summary['check_errors_total']}",
            "",
            "ROUND SUMMARIES",
            "---------------",
        ]
        for item in rounds:
            s = item.get("summary", {})
            lines.append(
                f"Round {s.get('round', '?')} | {s.get('finished_at', 'failed')} | "
                f"files={s.get('files_discovered', '?')} | "
                f"findings={s.get('findings_total', '?')} | "
                f"errors={s.get('error_count', '?')} | "
                f"duration={s.get('duration_seconds', '?')} sec"
            )
            for error in s.get("errors", []):
                lines.append(f"  ERROR in {error.get('check')}: {error.get('file')} — {error.get('error')}")
            if s.get("round_failure"):
                lines.append(f"  ROUND FAILURE: {s['round_failure']}")
        lines.extend(["", "FINDINGS", "--------"])
        if all_findings:
            for item in all_findings:
                lines.append(
                    f"[Round {item.get('round')}] [{item.get('severity')}] "
                    f"{item.get('category')} | {item.get('file')}:{item.get('line')} — {item.get('message')}"
                )
        else:
            lines.append("No findings were detected by the checks that ran. This does not prove the project is bug-free or secure.")
        lines.extend([
            "", "NOTES", "-----",
            *[f"- {note}" for note in summary["notes"]],
            "",
            "This report can contain repeated findings from different rounds. Review before sharing."
        ])
        text_path.write_text("\n".join(lines), encoding="utf-8")
        print()
        print("Audit stopped and reports saved.")
        print(f"Rounds completed: {summary['rounds_completed']}")
        print(f"Text report: {text_path}")
        print(f"JSON report: {json_path}")
    except Exception as exc:
        print(f"Could not write text report: {type(exc).__name__}: {str(exc)[:200]}")
    print("No project source files were intentionally modified or deleted.")


if __name__ == "__main__":
    main()
