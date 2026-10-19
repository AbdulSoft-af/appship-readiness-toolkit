"""Command-line interface for AppShip scanning, reporting and opt-in builds."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import sys
from pathlib import Path, PurePosixPath
from typing import Dict, List

from . import __version__
from .analyzer import analyze_files
from .artifact_verifier import verify_artifact, artifact_report_markdown, artifact_report_html
from .build_runner import run_build_and_test, content_digest
from .html_report import render_html_report
from .policy import ANDROID_PROFILES, DEFAULT_ANDROID_PROFILE, policy_snapshot
from .project_io import (
    apply_safe_fixes,
    create_zip_from_files,
    is_machine_specific_file,
    is_sensitive_local_file,
    load_folder,
    load_zip,
    _project_prefix,
)
from .reports import checklist_markdown, to_markdown


def _load_source(path_text: str):
    path = Path(path_text).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Source path was not found: {path}")
    if path.is_dir():
        files, notes = load_folder(str(path))
        kind = "folder"
        name = path.name or "Selected project"
    elif path.is_file() and path.suffix.lower() == ".zip":
        files, notes = load_zip(str(path))
        kind = "zip"
        name = path.stem
    else:
        raise ValueError("Source must be a folder or a .zip archive.")
    return path, files, notes, kind, name


def _write_text(path: str | Path, content: str):
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")
    return target


def _ensure_output_is_separate(destination: str | Path, source_path: Path, source_kind: str):
    output_path = Path(destination).expanduser().resolve()
    if output_path == source_path.resolve():
        raise ValueError("Output path matches the input source. Choose a separate destination to avoid overwriting your source.")
    if source_kind == "folder" and source_path.resolve() in output_path.parents:
        raise ValueError("Write reports and prepared bundles outside the scanned source folder to avoid polluting or overwriting project files.")
    return output_path


def _source_inventory(files: Dict[str, bytes], source_name: str) -> dict:
    records = []
    for name, data in sorted(files.items()):
        suffix = PurePosixPath(name).suffix.lower()
        records.append({
            "path": name,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "extension": suffix,
            "likely_sensitive_local_file": bool(is_sensitive_local_file(name, data)),
            "machine_specific": bool(is_machine_specific_file(name)),
        })
    return {
        "schema": "https://appship.dev/schemas/source-inventory/v1",
        "tool": "AppShip Readiness Toolkit",
        "tool_version": __version__,
        "project_name": source_name,
        "file_count": len(records),
        "content_digest_sha256": content_digest(files),
        "files": records,
        "note": "This is a source-file inventory with hashes, not a complete dependency SBOM or proof of artifact provenance.",
    }


def _tool_state(command: str) -> dict:
    executable = shutil.which(command)
    return {"tool": command, "available": bool(executable), "path": executable or None}


def doctor_report() -> dict:
    tools = ["python", "git", "java", "jarsigner", "apksigner", "gradle", "flutter", "dart", "adb", "node", "npm", "xcodebuild", "codesign", "ollama", "docker"]
    states = [_tool_state(item) for item in tools]
    return {
        "appship_version": __version__,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "tkinter_available": importlib.util.find_spec("tkinter") is not None,
        "toolchains": states,
        "guidance": [
            "Missing toolchains are not a scanner failure; they may be required only for the selected app framework.",
            "Android builds usually need a supported JDK, Android SDK and Gradle wrapper/tooling.",
            "iOS device/store builds require macOS and Xcode with valid signing setup.",
            "Ollama is optional and only used as a local AI endpoint by this version.",
        ],
    }


def _create_prepared_zip(
    files: Dict[str, bytes], report, notes: List[str], destination: str,
    allow_suspected_secrets: bool = False,
) -> List[str]:
    # Do not package signing material or machine-local SDK settings by default.
    excluded = [p for p, content in files.items() if is_sensitive_local_file(p, content) or is_machine_specific_file(p)]
    safe_source = {p: v for p, v in files.items() if p not in set(excluded)}
    patched, fix_notes = apply_safe_fixes(safe_source)
    updated_report = analyze_files(
        patched, report.project_name, "sanitized prepared source copy", report.android_app_category
    )
    if any(f.id == "SEC-001" for f in updated_report.findings) and not allow_suspected_secrets:
        raise ValueError(
            "A possible hard-coded secret remains in the prepared source. Remove/rotate the credential or verify a false positive locally. "
            "Only use --allow-suspected-secrets after manually confirming no real secret is present."
        )
    prefix = _project_prefix(patched)
    package_notes = list(notes) + fix_notes
    if excluded:
        package_notes.append("Excluded local-only/machine-specific files: " + ", ".join(excluded))
    if any(f.id == "SEC-001" for f in updated_report.findings):
        package_notes.append("WARNING: one or more possible hard-coded secrets remain; verify locally and rotate real exposed credentials before sharing.")
    additions = {
        prefix + "APPSTORE_PLAYSTORE_CHECKLIST.md": checklist_markdown(updated_report.stacks, updated_report.android_app_category).encode("utf-8"),
        prefix + "APPSHIP_READINESS_REPORT.md": to_markdown(updated_report, package_notes).encode("utf-8"),
        prefix + "APPSHIP_READINESS_REPORT.html": render_html_report(updated_report, package_notes).encode("utf-8"),
        prefix + "appship_readiness_report.json": json.dumps(updated_report.to_dict(), indent=2, ensure_ascii=False).encode("utf-8"),
        prefix + "APPSHIP_SAFE_FIX_LOG.txt": ("AppShip limited safe-fix log\n\n" + "\n".join("- " + note for note in fix_notes) + "\n\nThese deterministic changes do not prove that the app builds or is accepted by a Store.\n").encode("utf-8"),
        prefix + "APPSHIP_SOURCE_INVENTORY.json": json.dumps(_source_inventory(patched, report.project_name), indent=2, ensure_ascii=False).encode("utf-8"),
    }
    if excluded:
        additions[prefix + "APPSHIP_EXCLUDED_LOCAL_FILES.txt"] = (
            "Local-only/machine-specific files excluded from the prepared ZIP by default:\n\n"
            + "\n".join("- " + name for name in excluded)
            + "\n\nReconfigure these on a trusted build machine. Never share signing secrets.\n"
        ).encode("utf-8")
    create_zip_from_files(patched, destination, additions)
    return fix_notes + ([f"Excluded {len(excluded)} local-only/machine-specific file(s)."] if excluded else [])


def _validate_requested_outputs(args: argparse.Namespace, source_path: Path, source_kind: str):
    outputs = []
    for flag, label in [
        ("output", "readiness report"), ("checklist", "checklist"),
        ("inventory", "source inventory"), ("prepared_zip", "prepared ZIP"),
    ]:
        value = getattr(args, flag, None)
        if value:
            outputs.append((label, _ensure_output_is_separate(value, source_path, source_kind)))
    if getattr(args, "build_test", False):
        outputs.append(("Build & Test bundle", _ensure_output_is_separate(args.build_bundle, source_path, source_kind)))
    seen = {}
    for label, path in outputs:
        key = os.path.normcase(str(path))
        if key in seen:
            raise ValueError(f"The {label} output conflicts with the {seen[key]} output at {path}. Choose a different path for each output.")
        seen[key] = label


def _cmd_scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.build_test and not args.confirm_execute_build_scripts:
        parser.error("--build-test requires --confirm-execute-build-scripts because build scripts run code on your computer.")
    if args.allow_dependency_install and not args.build_test:
        parser.error("--allow-dependency-install can only be used with --build-test.")
    if args.allow_suspected_secrets and not args.prepared_zip:
        parser.error("--allow-suspected-secrets can only be used with --prepared-zip.")
    source_path, files, notes, kind, project_name = _load_source(args.source)
    _validate_requested_outputs(args, source_path, kind)
    report = analyze_files(files, project_name, f"{kind}: {source_path}", args.android_profile)
    notes = list(notes)

    format_name = args.format
    output = args.output
    if output and args.format == "auto":
        suffix = Path(output).suffix.lower()
        format_name = {".json": "json", ".html": "html", ".htm": "html", ".md": "markdown"}.get(suffix, "markdown")
    elif format_name == "auto":
        format_name = "markdown"

    if format_name == "json":
        report_text = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    elif format_name == "html":
        report_text = render_html_report(report, notes)
    else:
        report_text = to_markdown(report, notes)

    if output:
        _ensure_output_is_separate(output, source_path, kind)
        saved = _write_text(output, report_text)
        print(f"Report written: {saved}")
    else:
        print(f"AppShip {__version__} — {report.project_name}")
        print(f"Platforms: {', '.join(report.stacks)}")
        print(f"Policy profile: {report.android_app_category} (checked {report.policy_checked_on})")
        print(f"Files scanned: {report.files_scanned}; score: {report.indicative_score}/100 (prioritization aid only)")
        print("Findings: " + ", ".join(f"{key}={report.summary[key]}" for key in ("critical", "high", "medium", "low", "info")))
        for finding in report.findings[:min(15, args.top_findings)]:
            print(f"[{finding.severity.upper()}] {finding.id}: {finding.title} — {finding.path}")
        if len(report.findings) > min(15, args.top_findings):
            print(f"… {len(report.findings) - min(15, args.top_findings)} more; pass --output report.md to export all findings.")

    if args.checklist:
        _ensure_output_is_separate(args.checklist, source_path, kind)
        path = _write_text(args.checklist, checklist_markdown(report.stacks, report.android_app_category))
        print(f"Store checklist written: {path}")
    if args.inventory:
        _ensure_output_is_separate(args.inventory, source_path, kind)
        inventory = _source_inventory(files, project_name)
        path = _write_text(args.inventory, json.dumps(inventory, indent=2, ensure_ascii=False))
        print(f"Source inventory written: {path}")
    if args.prepared_zip:
        prepared_path = _ensure_output_is_separate(args.prepared_zip, source_path, kind)
        prepared_path.parent.mkdir(parents=True, exist_ok=True)
        prep_notes = _create_prepared_zip(files, report, notes, str(prepared_path), args.allow_suspected_secrets)
        print(f"Prepared ZIP written: {prepared_path}")
        for note in prep_notes:
            print(f"  - {note}")
        print("  - Scan and build-test this exact prepared ZIP before publication.")
    build_failed = False
    if args.build_test:
        bundle = _ensure_output_is_separate(args.build_bundle, source_path, kind)
        bundle.parent.mkdir(parents=True, exist_ok=True)
        print("WARNING: this is not a full OS sandbox. Build scripts can execute code as your user.")
        if args.allow_dependency_install:
            print("WARNING: network dependency installation is enabled; package lifecycle/build scripts may execute.")
        build_result = run_build_and_test(
            files, project_name, report, str(bundle),
            allow_dependency_install=args.allow_dependency_install,
            timeout_seconds=args.timeout,
        )
        print(build_result.summary())
        print(f"Build/test bundle: {build_result.bundle_path}")
        build_failed = not build_result.success
        if build_failed:
            print("BUILD/TEST FAILED OR COULD NOT BE VERIFIED. Inspect the bundle logs and toolchain warnings.", file=sys.stderr)
            return 1
    if args.strict and (report.summary.get("critical", 0) or report.summary.get("high", 0)):
        print("STRICT MODE FAILED: Critical/High findings remain. This is not a Store rejection prediction.", file=sys.stderr)
        return 1
    return 0


def _cmd_verify_artifact(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    report = verify_artifact(args.artifact)
    format_name = args.format
    output = args.output
    if output and format_name == "auto":
        suffix = Path(output).suffix.lower()
        format_name = {".json": "json", ".html": "html", ".htm": "html", ".md": "markdown"}.get(suffix, "markdown")
    elif format_name == "auto":
        format_name = "markdown"
    if format_name == "json":
        rendered = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    elif format_name == "html":
        rendered = artifact_report_html(report)
    else:
        rendered = artifact_report_markdown(report)
    if output:
        destination = _ensure_output_is_separate(output, Path(args.artifact).expanduser().resolve(), "file")
        _write_text(destination, rendered)
        print(f"Artifact report written: {destination}")
    else:
        print(rendered)
    print(f"Artifact status: {report.overall_status}")
    if report.overall_status == "FAIL":
        return 1
    if args.require_signature and report.overall_status != "PASS":
        print("Required cryptographic verification is not fully confirmed.", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appship",
        description="AppShip Readiness Toolkit — local-first mobile app preflight scanner.",
        epilog="Static checks are not a Store approval guarantee. Review official policy links before each submission.",
    )
    parser.add_argument("--version", action="version", version=f"AppShip {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a project folder or ZIP archive.")
    scan.add_argument("source", help="Project folder path or .zip archive")
    scan.add_argument("--android-profile", choices=list(ANDROID_PROFILES), default=DEFAULT_ANDROID_PROFILE,
                      help="Target API policy profile; standard is intended for general Android apps.")
    scan.add_argument("--format", choices=["auto", "markdown", "json", "html"], default="auto")
    scan.add_argument("--output", help="Optional readiness report path (.md, .json, or .html)")
    scan.add_argument("--checklist", help="Optional path to write a Store release checklist")
    scan.add_argument("--inventory", help="Optional JSON source inventory path (file hashes; not a full SBOM)")
    scan.add_argument("--prepared-zip", help="Optional sanitized ZIP with limited safe fixes and report bundle")
    scan.add_argument("--allow-suspected-secrets", action="store_true",
                      help="Override the default prepared-ZIP block when a possible hard-coded secret remains; use only after manual verification")
    scan.add_argument("--strict", action="store_true", help="Exit with status 1 if Critical/High findings exist")
    scan.add_argument("--top-findings", type=int, default=15, help="Maximum summary findings shown on console (0-15)")
    scan.add_argument("--build-test", action="store_true", help="Run selected build/test plan in a temporary copy")
    scan.add_argument("--confirm-execute-build-scripts", action="store_true",
                      help="Explicit confirmation: build scripts may execute code on this computer")
    scan.add_argument("--allow-dependency-install", action="store_true",
                      help="Allow network dependency resolution/lifecycle scripts when supported")
    scan.add_argument("--build-bundle", default="appship_build_test_bundle.zip", help="Output ZIP path for build/test artifacts")
    scan.add_argument("--timeout", type=int, default=900, help="Per-step timeout in seconds (60-3600)")
    scan.set_defaults(handler=_cmd_scan)

    artifact = subparsers.add_parser("verify-artifact", help="Inspect an APK/AAB/IPA and try local signature verification.")
    artifact.add_argument("artifact", help="Path to a generated .apk, .aab or .ipa file")
    artifact.add_argument("--format", choices=["auto", "markdown", "json", "html"], default="auto")
    artifact.add_argument("--output", help="Optional path for the artifact verification report")
    artifact.add_argument("--require-signature", action="store_true",
                          help="Exit non-zero unless every required check is PASS, including cryptographic signature verification")
    artifact.set_defaults(handler=_cmd_verify_artifact)

    doctor = subparsers.add_parser("doctor", help="Check local toolchain availability.")
    doctor.add_argument("--json", dest="json_path", help="Optional file path to write the diagnostic report")
    doctor.set_defaults(handler=_cmd_doctor)

    policies = subparsers.add_parser("policies", help="Show the dated policy snapshot and official links.")
    policies.add_argument("--json", dest="json_path", help="Optional file path to write the policy snapshot")
    policies.set_defaults(handler=_cmd_policies)
    return parser


def _cmd_doctor(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    report = doctor_report()
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json_path:
        path = _write_text(args.json_path, rendered)
        print(f"Diagnostic report written: {path}")
    print(f"AppShip {report['appship_version']} | Python {report['python_version']} | {report['platform']}")
    print(f"Tkinter: {'available' if report['tkinter_available'] else 'not available'}")
    for item in report["toolchains"]:
        print(f"{'[OK]' if item['available'] else '[--]'} {item['tool']}: {item['path'] or 'not found'}")
    print("Missing toolchains may be irrelevant to your chosen framework. See the README for requirements.")
    return 0


def _cmd_policies(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    snapshot = policy_snapshot()
    rendered = json.dumps(snapshot, indent=2, ensure_ascii=False)
    if args.json_path:
        path = _write_text(args.json_path, rendered)
        print(f"Policy snapshot written: {path}")
    print(f"Policy snapshot last checked: {snapshot['checked_on']}")
    for key, value in snapshot["android_profiles"].items():
        print(f"{key}: API {value['required_target_api']}+ — {value['label']}")
    print("Official sources:")
    for key, value in snapshot["official_sources"].items():
        print(f"  {key}: {value}")
    print(snapshot["disclaimer"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "top_findings", None) is not None:
        args.top_findings = max(0, min(15, args.top_findings))
    try:
        return args.handler(args, parser)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"AppShip error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
