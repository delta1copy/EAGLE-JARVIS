#!/usr/bin/env python3
"""
EAGLE JARVIS read-only overnight audit.
- Scans only the project folder containing this script (or --root if supplied).
- Does not modify or delete project files.
- Does not print secret values; .env contents are never read into the report.
- Writes reports to a separate reports/ folder inside the project.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".idea", ".vscode", "dist", "build", "reports"
}
TEXT_SUFFIXES = {".py", ".html", ".htm", ".js", ".mjs", ".cjs", ".css", ".json", ".toml", ".ini", ".cfg", ".md", ".txt", ".yml", ".yaml"}
SECRET_PATTERNS = [
    ("possible API key/token assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})"
    )),
    ("Google API key pattern", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
]
URL_RE = re.compile(r"https?://(?:127\.0\.0\.1|localhost):(\d+)", re.I)


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def collect_files(root: Path):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if path.suffix.lower() in TEXT_SUFFIXES:
                yield path


def safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def scan_python(path: Path, root: Path, findings: list, stats: dict):
    rel = safe_rel(path, root)
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=rel)
        stats["python_files_parsed"] += 1
    except SyntaxError as exc:
        findings.append({
            "severity": "HIGH", "category": "Python syntax",
            "file": rel, "line": exc.lineno or 0,
            "message": f"Syntax error: {exc.msg}. Check this line before running the app."
        })
        stats["python_files_with_syntax_errors"] += 1
        return
    except Exception as exc:
        findings.append({
            "severity": "LOW", "category": "Read error", "file": rel,
            "line": 0, "message": f"Could not inspect file ({type(exc).__name__})."
        })
        return

    names = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.setdefault((type(node).__name__, node.name), []).append(node.lineno)
    for (kind, name), lines in names.items():
        if len(lines) > 1:
            findings.append({
                "severity": "MEDIUM", "category": "Duplicate definition",
                "file": rel, "line": lines[-1],
                "message": f"{kind} '{name}' is defined multiple times at lines {', '.join(map(str, lines))}."
            })

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                findings.append({
                    "severity": "HIGH", "category": "Risky Python pattern",
                    "file": rel, "line": getattr(node, "lineno", 0),
                    "message": "Use of eval() found; review whether untrusted input can reach it."
                })
            elif node.func.id == "exec":
                findings.append({
                    "severity": "MEDIUM", "category": "Risky Python pattern",
                    "file": rel, "line": getattr(node, "lineno", 0),
                    "message": "Use of exec() found; review carefully."
                })


def scan_text(path: Path, root: Path, findings: list, stats: dict):
    rel = safe_rel(path, root)
    # Never open .env files, private keys, or common credential files.
    if path.name.lower() in {".env", ".env.local", ".env.production", "credentials.json", "service-account.json"}:
        stats["sensitive_files_skipped"] += 1
        return
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    stats["text_files_scanned"] += 1

    for line_no, line in enumerate(content.splitlines(), 1):
        # Never include the matched value or the source line in findings.
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "severity": "HIGH", "category": "Possible exposed secret",
                    "file": rel, "line": line_no,
                    "message": f"{label} pattern found. Value hidden; review locally and rotate the credential if it is real."
                })
                break

    if path.name.lower() == "index.html":
        ports = sorted(set(URL_RE.findall(content)))
        if ports:
            stats["frontend_localhost_ports"][rel] = ports
        if "fetch(" not in content and "XMLHttpRequest" not in content:
            findings.append({
                "severity": "INFO", "category": "Frontend review",
                "file": rel, "line": 0,
                "message": "No fetch() or XMLHttpRequest string found; verify how the dashboard sends API requests."
            })


def run_optional_pip_audit(root: Path, findings: list, stats: dict, timeout: int):
    py = root / "backend" / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        py = root / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        stats["pip_audit"] = "Skipped: project virtual-environment Python not found."
        return
    try:
        # pip-audit is optional; if unavailable, no install is attempted.
        check = subprocess.run(
            [str(py), "-m", "pip_audit", "--version"],
            capture_output=True, text=True, timeout=15
        )
        if check.returncode != 0:
            stats["pip_audit"] = "Skipped: pip-audit is not installed; scanner did not install packages."
            return
        result = subprocess.run(
            [str(py), "-m", "pip_audit", "--format", "json"],
            cwd=str(root), capture_output=True, text=True, timeout=timeout
        )
        stats["pip_audit"] = "Completed" if result.returncode == 0 else "Completed with findings or errors."
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                vulnerabilities = []
                if isinstance(data, list):
                    for item in data:
                        vulns = item.get("vulns", []) if isinstance(item, dict) else []
                        for vuln in vulns:
                            vulnerabilities.append((item.get("name", "unknown"), item.get("version", "?"), vuln.get("id", "unknown")))
                stats["dependency_vulnerabilities"] = len(vulnerabilities)
                for package, version, vuln_id in vulnerabilities[:100]:
                    findings.append({
                        "severity": "HIGH", "category": "Dependency vulnerability",
                        "file": "installed environment", "line": 0,
                        "message": f"{package} {version}: {vuln_id}. Review and update deliberately."
                    })
            except json.JSONDecodeError:
                stats["pip_audit_note"] = "pip-audit returned output that could not be parsed as JSON."
        if result.returncode not in (0, 1):
            stats["pip_audit_note"] = (result.stderr or "pip-audit exited unexpectedly.")[:500]
    except subprocess.TimeoutExpired:
        stats["pip_audit"] = f"Timed out after {timeout} seconds; no changes made."
    except Exception as exc:
        stats["pip_audit"] = f"Skipped due to {type(exc).__name__}; no changes made."


def build_capability_notes(root: Path, files: list[Path], stats: dict):
    names = {p.name.lower() for p in files}
    joined_names = " ".join(str(p.relative_to(root)).lower() for p in files)
    notes = [
        "This is a static audit, not a penetration test and not a guarantee that the app is secure.",
        "AI quality and memory cannot be proven from source inspection alone; test them interactively.",
        "Do not automatically execute shell commands suggested by an AI model.",
        "For microphone, calendar, email, and computer-control features, require explicit user permission and clear confirmations for consequential actions."
    ]
    if "index.html" in names:
        notes.append("Dashboard file detected: manually test loading states, network failures, and user-visible error messages.")
    if "main.py" in names or "app.py" in names:
        notes.append("Python web-app entry file detected: test health and command endpoints separately.")
    if ".env" in joined_names:
        notes.append("Environment file name detected, but secret files are deliberately skipped.")
    stats["capability_review"] = notes


def main():
    parser = argparse.ArgumentParser(description="Read-only EAGLE JARVIS project audit")
    parser.add_argument("--root", default=None, help="Project root (default: folder containing this script)")
    parser.add_argument("--dependency-timeout", type=int, default=180, help="Maximum seconds for optional pip-audit if installed")
    args = parser.parse_args()

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent
    if not root.exists() or not root.is_dir():
        print("ERROR: project root does not exist or is not a folder.")
        sys.exit(2)

    started = time.time()
    files = list(collect_files(root))
    findings = []
    stats = {
        "project_root": str(root),
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
        "files_discovered": len(files),
        "python_files_parsed": 0,
        "python_files_with_syntax_errors": 0,
        "text_files_scanned": 0,
        "sensitive_files_skipped": 0,
        "frontend_localhost_ports": {},
        "pip_audit": "Not run",
    }

    for path in files:
        if path.suffix.lower() == ".py":
            scan_python(path, root, findings, stats)
        scan_text(path, root, findings, stats)

    build_capability_notes(root, files, stats)
    run_optional_pip_audit(root, findings, stats, max(30, args.dependency_timeout))

    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    stats["findings_by_severity"] = counts
    stats["findings_total"] = len(findings)
    stats["duration_seconds"] = round(time.time() - started, 2)
    stats["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")

    report_dir = root / "reports"
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / f"eagle_jarvis_audit_{now_stamp()}.json"
    summary_path = report_dir / f"eagle_jarvis_audit_{now_stamp()}.txt"
    report = {"summary": stats, "findings": findings}
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "EAGLE JARVIS OVERNIGHT AUDIT",
        "=" * 32,
        f"Project: {root}",
        f"Started: {stats['started_at']}",
        f"Finished: {stats['finished_at']}",
        f"Duration: {stats['duration_seconds']} seconds",
        f"Files discovered: {stats['files_discovered']}",
        f"Python files parsed: {stats['python_files_parsed']}",
        f"Python syntax-error files: {stats['python_files_with_syntax_errors']}",
        f"Text files scanned: {stats['text_files_scanned']}",
        f"Sensitive files skipped: {stats['sensitive_files_skipped']}",
        f"Dependency audit: {stats['pip_audit']}",
        f"Findings: {stats['findings_total']} {counts}",
        "",
        "FINDINGS",
        "--------",
    ]
    if findings:
        for item in findings:
            lines.append(f"[{item['severity']}] {item['category']} | {item['file']}:{item['line']} — {item['message']}")
    else:
        lines.append("No static findings were detected by these checks. This does not prove the project is secure.")
    lines.extend(["", "CAPABILITY / NEXT-STEP NOTES"])
    lines.extend(f"- {note}" for note in stats["capability_review"])
    lines.extend(["", "SAFETY", "------",
                  "Read-only scan: no project source files were changed or deleted.",
                  "Secret-bearing files were skipped. Review reports before sharing them.",
                  "This is not a full penetration test. Dependency audit runs only if pip-audit is already installed."])
    summary_path.write_text("\n".join(lines), encoding="utf-8")

    print("EAGLE JARVIS audit finished.")
    print(f"Files discovered: {stats['files_discovered']}")
    print(f"Findings: {stats['findings_total']} {counts}")
    print(f"Duration: {stats['duration_seconds']} seconds")
    print(f"Text report: {summary_path}")
    print(f"JSON report: {report_path}")
    if stats["duration_seconds"] < 600:
        print("Note: scan finished in under 10 minutes; it does not add artificial delays.")
    print("No project source files were modified or deleted.")


if __name__ == "__main__":
    main()
