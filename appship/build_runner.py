"""Opt-in local build/test runner for AppShip.

Runs trusted project build tooling against a temporary source copy, never the selected
source directory itself. This is workspace isolation, NOT an operating-system sandbox.
Build scripts can execute arbitrary code on the user's machine; the UI requires consent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import zipfile

from .project_io import safe_member_name, is_sensitive_local_file, is_machine_specific_file
from .reports import to_markdown, checklist_markdown

SENSITIVE_NAME_PARTS = (".npmrc", ".pypirc", "credentials", "service-account", "secrets.", "key.properties")
SENSITIVE_SUFFIXES = {".jks", ".keystore", ".p12", ".pfx", ".pem", ".key"}
MAX_CAPTURE_CHARS = 200_000
DEFAULT_TIMEOUT = 900


@dataclass
class StepResult:
    label: str
    command: List[str]
    cwd: str
    status: str
    return_code: Optional[int]
    duration_seconds: float
    output: str = ""

    def as_dict(self):
        return {
            "label": self.label,
            "command": self.command,
            "cwd": self.cwd,
            "status": self.status,
            "return_code": self.return_code,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class BuildResult:
    success: bool
    log: str
    steps: List[StepResult] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    bundle_path: str = ""
    input_digest: str = ""

    def summary(self) -> str:
        passed = sum(1 for s in self.steps if s.status == "PASS")
        failed = sum(1 for s in self.steps if s.status in {"FAIL", "TIMEOUT", "ERROR"})
        skipped = sum(1 for s in self.steps if s.status == "SKIP")
        return f"{'PASS' if self.success else 'NEEDS ATTENTION'} — {passed} passed, {failed} failed, {skipped} skipped. Artifacts: {len(self.artifacts)}."


def content_digest(files: Dict[str, bytes]) -> str:
    import hashlib
    hasher = hashlib.sha256()
    for name in sorted(files):
        hasher.update(name.encode("utf-8", "replace"))
        hasher.update(b"\0")
        hasher.update(files[name])
        hasher.update(b"\0")
    return hasher.hexdigest()


def _is_sensitive_path(path: str) -> bool:
    # Compatibility helper for the build workspace; content-aware checks are applied below.
    p = PurePosixPath(path)
    low = p.name.lower()
    return low in {".env", ".env.local", ".env.production", ".env.development", ".env.test", ".npmrc", ".pypirc", "key.properties"} or p.suffix.lower() in SENSITIVE_SUFFIXES or "service-account" in low or "credentials" in low


def _redact_log(value: str) -> str:
    """Redact common accidental secret echoes before logs are included in export bundles."""
    value = re.sub(r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret|storepassword|keypassword)\s*([:=])\s*[^\s,;]+", r"\1\2[REDACTED]", value)
    value = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[A-Za-z0-9-]{20,})\b", "[REDACTED TOKEN]", value)
    value = re.sub(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "[REDACTED PRIVATE KEY BLOCK]", value, flags=re.I | re.S)
    return value


def _safe_build_env() -> Dict[str, str]:
    env = os.environ.copy()
    secret_pattern = re.compile(r"(TOKEN|SECRET|PASSWORD|PRIVATE.?KEY|API.?KEY|AWS_|AZURE_|GITHUB_|GOOGLE_APPLICATION_CREDENTIALS|SIGNING)", re.I)
    for key in list(env):
        if secret_pattern.search(key) or key.upper() in {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GRADLE_OPTS", "NODE_OPTIONS", "PYTHONPATH"}:
            env.pop(key, None)
    # Disable telemetry where common toolchains support an env-based opt-out.
    env.setdefault("CI", "1")
    env.setdefault("TERM", "dumb")
    return env


def _safe_relative_join(root: Path, relative: str) -> Path:
    if not safe_member_name(relative):
        raise ValueError(f"Unsafe source path rejected: {relative}")
    result = (root / Path(*PurePosixPath(relative).parts)).resolve()
    if root.resolve() not in result.parents and result != root.resolve():
        raise ValueError(f"Source path escapes workspace: {relative}")
    return result


def _write_workspace(files: Dict[str, bytes], root: Path) -> List[str]:
    warnings = []
    for name, data in files.items():
        if not safe_member_name(name):
            warnings.append(f"Skipped unsafe path: {name}")
            continue
        if _is_sensitive_path(name) or is_sensitive_local_file(name, data):
            warnings.append(f"Excluded potentially sensitive local file from build workspace: {name}")
            continue
        if is_machine_specific_file(name):
            warnings.append(f"Excluded machine-specific file from build workspace: {name}. Configure SDK/toolchain paths in the build environment.")
            continue
        target = _safe_relative_join(root, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if target.name in {"gradlew", "flutterw"} and os.name != "nt":
            try:
                target.chmod(target.stat().st_mode | 0o111)
            except OSError:
                pass
    return warnings


def _find_wrapper(root: Path) -> Optional[Tuple[Path, Path]]:
    names = {"gradlew.bat", "gradlew"}
    candidates = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in {".git", "node_modules", "vendor", "pods", "build", "dist", ".gradle", "deriveddata", ".dart_tool"}]
        for name in files:
            if name in names:
                path = Path(current) / name
                # Prefer the wrapper closest to the Android project files (settings.gradle present).
                score = len(path.relative_to(root).parts)
                settings = any((Path(current) / x).exists() for x in ("settings.gradle", "settings.gradle.kts"))
                candidates.append((0 if settings else 1, score, path.parent, path))
    if candidates:
        candidates.sort()
        _, _, cwd, wrapper = candidates[0]
        return cwd, wrapper
    return None


def _run_step(label: str, command: List[str], cwd: Path, timeout: int, env: Dict[str, str]) -> StepResult:
    import time
    start = time.monotonic()
    try:
        actual_command = list(command)
        if os.name == "nt" and actual_command and str(actual_command[0]).lower().endswith((".bat", ".cmd")):
            # Windows batch wrappers need cmd.exe when shell=True is intentionally avoided.
            actual_command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c"] + actual_command
        completed = subprocess.run(
            actual_command,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
        out = completed.stdout[-MAX_CAPTURE_CHARS:]
        status = "PASS" if completed.returncode == 0 else "FAIL"
        return StepResult(label, command, str(cwd), status, completed.returncode, time.monotonic() - start, out)
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return StepResult(label, command, str(cwd), "TIMEOUT", None, time.monotonic() - start, str(raw)[-MAX_CAPTURE_CHARS:] + f"\nTimed out after {timeout} seconds.")
    except OSError as exc:
        return StepResult(label, command, str(cwd), "ERROR", None, time.monotonic() - start, f"Could not start command: {exc}")


def _package_results(destination_zip: str, result: BuildResult, report, checklist: str, workspace: Path) -> None:
    from datetime import datetime
    md = [
        "# AppShip Build & Test Report", "",
        f"- **Generated:** {datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}",
        f"- **Result:** {'PASS' if result.success else 'NEEDS ATTENTION'}",
        f"- **Summary:** {result.summary()}",
        "- **Security note:** Commands were run on a temporary copy, not the original selected folder. This is not a full OS sandbox; only run builds for source you trust.",
        "", "## Steps", "", "| Step | Status | Duration (s) | Exit |", "|---|---|---:|---:|",
    ]
    for s in result.steps:
        md.append(f"| {s.label.replace('|', '/') } | {s.status} | {s.duration_seconds:.1f} | {s.return_code if s.return_code is not None else '—'} |")
    md.extend(["", "## Warnings", ""])
    md.extend([f"- {x}" for x in result.warnings] or ["- None."])
    md.extend(["", "## Artifacts included", ""])
    md.extend([f"- `{x}`" for x in result.artifacts] or ["- No installable/release artifact was produced."])
    md.extend(["", "## Important", "", "A successful build does not verify app behavior, signing identity, store disclosures, listing assets, or store approval. Verify the signature and test the exact release artifact.", ""])
    with zipfile.ZipFile(destination_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=4) as zf:
        zf.writestr("APPSHIP_BUILD_TEST_REPORT.md", "\n".join(md))
        zf.writestr("APPSHIP_BUILD_LOG.txt", result.log)
        if report is not None:
            zf.writestr("APPSHIP_READINESS_REPORT.md", to_markdown(report, result.warnings))
        zf.writestr("APPSTORE_PLAYSTORE_CHECKLIST.md", checklist)
        zf.writestr("APPSHIP_BUILD_STEPS.json", json.dumps([s.as_dict() for s in result.steps], indent=2, ensure_ascii=False))
        used_names = set()
        for artifact in result.artifacts:
            p = Path(artifact)
            if p.is_file():
                # Avoid duplicate ZIP entry names when separate modules emit same-named packages.
                arc_name = p.name
                if arc_name in used_names:
                    arc_name = f"{p.parent.name}_{p.name}"
                stem = Path(arc_name).stem
                suffix = Path(arc_name).suffix
                counter = 2
                candidate = arc_name
                while candidate in used_names:
                    candidate = f"{stem}_{counter}{suffix}"
                    counter += 1
                arc_name = candidate
                used_names.add(arc_name)
                # Store already-compressed mobile packages without recompression where possible.
                method = zipfile.ZIP_STORED if p.suffix.lower() in {".apk", ".aab", ".ipa", ".zip"} else zipfile.ZIP_DEFLATED
                zf.write(p, arcname="release_artifacts/" + arc_name, compress_type=method)


def run_build_and_test(
    files: Dict[str, bytes],
    project_name: str,
    report=None,
    destination_zip: str = "appship_build_bundle.zip",
    allow_dependency_install: bool = False,
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> BuildResult:
    """Run build/test commands against a temporary copy and package logs/artifacts.

    A human must consent before calling. Network package installation is disabled by
    default and enabled only by explicit user choice. No shell=True is used.
    """
    if not files:
        raise ValueError("No project files were provided.")
    try:
        timeout_seconds = max(60, min(int(timeout_seconds), 3600))
    except Exception:
        timeout_seconds = DEFAULT_TIMEOUT
    digest = content_digest(files)
    result = BuildResult(False, "", [], [], [], str(destination_zip), digest)
    checklist = checklist_markdown(report.stacks if report is not None else [], report.android_app_category if report is not None else "standard")

    with tempfile.TemporaryDirectory(prefix="appship_build_") as temp:
        temp_root = Path(temp)
        workspace = temp_root / "project"
        workspace.mkdir()
        result.warnings.extend(_write_workspace(files, workspace))
        env = _safe_build_env()
        lower_paths = [p.lower() for p in files]
        joined_text = "\n".join(
            v.decode("utf-8", "ignore")[:300_000]
            for p, v in files.items()
            if p.lower().endswith(("pubspec.yaml", "package.json", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"))
            and len(v) < 500_000
        ).lower()
        has_flutter = any(PurePosixPath(p).name.lower() == "pubspec.yaml" for p in files)
        has_ios_native = any(".xcodeproj/project.pbxproj" in p.lower() or p.lower().endswith(".xcworkspace/contents.xcworkspacedata") for p in files)
        has_node = any(PurePosixPath(p).name.lower() == "package.json" for p in files)
        steps: List[StepResult] = []

        def run(label: str, cmd: List[str], cwd: Path):
            step = _run_step(label, cmd, cwd, timeout_seconds, env)
            steps.append(step)
            return step

        if has_flutter:
            flutter = shutil.which("flutter")
            if not flutter:
                result.warnings.append("Flutter SDK is not installed or not on PATH; install Flutter and Android toolchain, then retry.")
                steps.append(StepResult("Flutter toolchain detection", ["flutter", "--version"], str(workspace), "ERROR", None, 0, result.warnings[-1]))
            else:
                root_candidates = [workspace / p for p in files if PurePosixPath(p).name.lower() == "pubspec.yaml"]
                pubspec = sorted(root_candidates, key=lambda p: len(p.parts))[0]
                flutter_root = pubspec.parent
                if allow_dependency_install:
                    run("Flutter dependency resolution (network allowed)", [flutter, "pub", "get"], flutter_root)
                else:
                    result.warnings.append("Flutter dependency installation was not enabled. Analysis/tests/build use --no-pub and require cached dependencies. This is not strict network isolation; native build tooling may still attempt network access for missing toolchains/dependencies.")
                run("Flutter static analysis", [flutter, "analyze", "--no-pub"], flutter_root)
                if any("/test/" in ("/" + p.lower()) or p.lower().startswith("test/") for p in files):
                    run("Flutter tests", [flutter, "test", "--no-pub"], flutter_root)
                else:
                    steps.append(StepResult("Flutter tests", [flutter, "test", "--no-pub"], str(flutter_root), "SKIP", None, 0, "No test/ source files were detected."))
                run("Flutter Android debug build", [flutter, "build", "apk", "--debug", "--no-pub"], flutter_root)
                if any("android" in p.lower() for p in files):
                    run("Flutter Android release bundle attempt", [flutter, "build", "appbundle", "--release", "--no-pub"], flutter_root)
        else:
            wrapper = _find_wrapper(workspace)
            is_android = any(p.endswith("androidmanifest.xml") for p in lower_paths) or wrapper is not None
            if is_android:
                if wrapper:
                    gradle_cwd, wrapper_path = wrapper
                    offline_arg = [] if allow_dependency_install else ["--offline"]
                    command = [str(wrapper_path), "--no-daemon", "--stacktrace"] + offline_arg + ["test", "assembleDebug"]
                    run("Gradle tests + Android debug build", command, gradle_cwd)
                    # Release bundling is a separate gate. It may need user-managed upload signing.
                    run("Android release App Bundle attempt", [str(wrapper_path), "--no-daemon", "--stacktrace"] + offline_arg + ["bundleRelease"], gradle_cwd)
                else:
                    gradle = shutil.which("gradle")
                    if gradle:
                        offline_arg = [] if allow_dependency_install else ["--offline"]
                        run("Gradle tests + Android debug build", [gradle, "--no-daemon", "--stacktrace"] + offline_arg + ["test", "assembleDebug"], workspace)
                        run("Android release App Bundle attempt", [gradle, "--no-daemon", "--stacktrace"] + offline_arg + ["bundleRelease"], workspace)
                    else:
                        msg = "No Gradle wrapper or installed Gradle command was detected. Include Gradle wrapper files or install Gradle."
                        result.warnings.append(msg)
                        steps.append(StepResult("Gradle toolchain detection", ["gradle", "--version"], str(workspace), "ERROR", None, 0, msg))
            else:
                result.warnings.append("No runnable Android/Flutter build plan was detected in this project.")
                steps.append(StepResult("Build plan detection", [], str(workspace), "SKIP", None, 0, result.warnings[-1]))

        # Only treat package.json scripts as React Native tests when React Native is actually declared.
        # Generic Node projects may have arbitrary scripts unrelated to a mobile app.
        if has_node:
            package_candidates = sorted(
                [workspace / p for p in files if PurePosixPath(p).name.lower() == "package.json"],
                key=lambda p: len(p.parts),
            )
            package_records = []
            for candidate in package_candidates:
                try:
                    parsed = json.loads(candidate.read_text(encoding="utf-8"))
                except Exception:
                    parsed = {}
                deps_for_candidate = {}
                if isinstance(parsed, dict):
                    for key in ("dependencies", "devDependencies", "peerDependencies"):
                        if isinstance(parsed.get(key), dict):
                            deps_for_candidate.update(parsed[key])
                package_records.append((candidate, parsed, deps_for_candidate))
            chosen_record = next((r for r in package_records if "react-native" in r[2] or "expo" in r[2]), package_records[0])
            package_path, package_json, deps = chosen_record
            is_react_native = "react-native" in deps or "expo" in deps
            scripts = package_json.get("scripts", {}) if isinstance(package_json, dict) else {}
            if is_react_native and isinstance(scripts, dict) and "test" in scripts:
                npm = shutil.which("npm")
                if not npm:
                    result.warnings.append("React Native package has a test script, but npm was not found on PATH.")
                elif not allow_dependency_install:
                    steps.append(StepResult("React Native JavaScript tests", [npm, "test"], str(package_path.parent), "SKIP", None, 0, "Dependency installation was not enabled. Enable it only for trusted projects to run npm ci and package scripts."))
                else:
                    lock = package_path.parent / "package-lock.json"
                    if lock.exists():
                        install = run("npm ci (network allowed)", [npm, "ci", "--no-audit", "--no-fund"], package_path.parent)
                    else:
                        install = StepResult("npm ci", [npm, "ci"], str(package_path.parent), "SKIP", None, 0, "package-lock.json not found; reproducible npm ci skipped.")
                        steps.append(install)
                    if install.status == "PASS":
                        run("React Native JavaScript tests", [npm, "test", "--", "--watchAll=false"], package_path.parent)
            elif is_react_native:
                result.warnings.append("React Native project detected, but no npm test script was declared in package.json.")
            else:
                result.warnings.append("A package.json was found but no React Native/Expo dependency was declared; its scripts were not executed.")

        # iOS build requires macOS/Xcode and a selected scheme; do not imply Windows can build signed iOS binaries.
        if has_ios_native:
            xcodebuild = shutil.which("xcodebuild")
            if platform.system() != "Darwin" or not xcodebuild:
                msg = "iOS native build skipped: Apple requires macOS/Xcode build tooling. Use a Mac with a selected Xcode scheme to Archive/sign/upload."
                result.warnings.append(msg)
                steps.append(StepResult("iOS build", ["xcodebuild", "-archive"], str(workspace), "SKIP", None, 0, msg))
            else:
                projects = [p for p in workspace.rglob("*.xcworkspace") if "pods" not in {part.lower() for part in p.parts}]
                projects.sort(key=lambda p: (len(p.parts), p.name.lower()))
                project_kind = "-workspace"
                if not projects:
                    projects = [p for p in workspace.rglob("*.xcodeproj") if "pods" not in {part.lower() for part in p.parts}]
                    projects.sort(key=lambda p: (len(p.parts), p.name.lower()))
                    project_kind = "-project"
                if projects:
                    selected = projects[0]
                    list_step = run("Xcode project/scheme discovery", [xcodebuild, "-list", "-json", project_kind, str(selected)], workspace)
                    schemes = []
                    targets = []
                    if list_step.status == "PASS":
                        try:
                            listing = json.loads(list_step.output)
                            section = listing.get("workspace") or listing.get("project") or {}
                            schemes = section.get("schemes", []) if isinstance(section, dict) else []
                            targets = section.get("targets", []) if isinstance(section, dict) else []
                        except (json.JSONDecodeError, AttributeError):
                            result.warnings.append("Xcode returned an unrecognized scheme listing; open the project in Xcode and select the production scheme manually.")
                    project_name_hint = selected.stem.lower()
                    chosen_scheme = next((x for x in schemes if str(x).lower() == project_name_hint), None)
                    if not chosen_scheme and len(schemes) == 1:
                        chosen_scheme = schemes[0]
                    if chosen_scheme:
                        build_args = [xcodebuild, project_kind, str(selected), "-scheme", str(chosen_scheme), "-destination", "generic/platform=iOS Simulator", "CODE_SIGNING_ALLOWED=NO", "build"]
                        run("Xcode iOS Simulator build (unsigned)", build_args, workspace)
                        if any("test" in str(t).lower() for t in targets):
                            xcrun = shutil.which("xcrun")
                            simulator_udid = None
                            if xcrun:
                                simulator_step = run("Available iOS Simulator discovery", [xcrun, "simctl", "list", "devices", "available", "--json"], workspace)
                                if simulator_step.status == "PASS":
                                    try:
                                        device_listing = json.loads(simulator_step.output)
                                        candidates = []
                                        for runtime, devices in device_listing.get("devices", {}).items():
                                            if "ios" not in runtime.lower() or not isinstance(devices, list):
                                                continue
                                            for device in devices:
                                                if device.get("isAvailable") and "iphone" in str(device.get("name", "")).lower() and device.get("udid"):
                                                    candidates.append((str(device.get("name", "")), str(device["udid"])))
                                        if candidates:
                                            candidates.sort(key=lambda item: (item[0].lower(), item[1]))
                                            simulator_udid = candidates[0][1]
                                    except (json.JSONDecodeError, AttributeError, TypeError):
                                        result.warnings.append("Could not parse available iOS Simulator devices; Xcode tests were not started.")
                            if simulator_udid:
                                test_args = [xcodebuild, project_kind, str(selected), "-scheme", str(chosen_scheme), "-destination", f"platform=iOS Simulator,id={simulator_udid}", "CODE_SIGNING_ALLOWED=NO", "test"]
                                run("Xcode iOS tests", test_args, workspace)
                            else:
                                result.warnings.append("Xcode test target exists, but no available iPhone Simulator UDID was found. Install/boot an iOS Simulator in Xcode and run tests again.")
                                steps.append(StepResult("Xcode iOS tests", [xcodebuild, "test"], str(workspace), "SKIP", None, 0, "No usable iPhone Simulator was found; hard-coded simulator names are deliberately avoided."))
                        else:
                            steps.append(StepResult("Xcode iOS tests", [xcodebuild, "test"], str(workspace), "SKIP", None, 0, "No target with a test-like name was found in the Xcode project listing; add/run tests manually."))
                        result.warnings.append("Xcode simulator build is unsigned. It is not a Store-uploadable IPA; create a signed Archive with your Apple Developer team and a verified scheme in Xcode.")
                    else:
                        result.warnings.append("Could not safely choose one production Xcode scheme. Open Xcode, select the app scheme, configure signing, then Archive and upload manually. Detected schemes: " + (", ".join(map(str, schemes)) or "none"))
                else:
                    result.warnings.append("No .xcodeproj or .xcworkspace bundle was found. A complete iOS project and supported Xcode installation are required.")

        result.steps = steps
        for step in steps:
            result.log += (
                f"\n{'=' * 88}\n{step.label} — {step.status}\n"
                f"cwd: {step.cwd}\ncommand: {json.dumps(step.command, ensure_ascii=False)}\n"
                f"duration: {step.duration_seconds:.1f}s; exit: {step.return_code}\n{'-' * 88}\n"
                f"{step.output}\n"
            )
        result.log = _redact_log(result.log[-1_000_000:])
        # Collect mobile packages only; do not package secrets or the entire working tree.
        artifact_candidates = []
        allowed_suffixes = {".aab", ".apk", ".ipa"}
        skip_artifact_scan_dirs = {".git", "node_modules", "vendor", "pods", ".gradle", ".dart_tool", "coverage", "__pycache__"}
        for current, dirs, names in os.walk(workspace):
            dirs[:] = [d for d in dirs if d.lower() not in skip_artifact_scan_dirs]
            for name in names:
                p = Path(current) / name
                if p.suffix.lower() not in allowed_suffixes:
                    continue
                try:
                    if p.stat().st_size > 0:
                        artifact_candidates.append(p)
                except OSError:
                    pass
        # Keep latest/largest package per name unique; avoid including intermediate duplicate copies.
        used_names = set()
        for p in sorted(artifact_candidates, key=lambda x: (x.suffix.lower() != ".aab", -x.stat().st_mtime if x.exists() else 0)):
            arc_name = p.name
            if arc_name in used_names:
                arc_name = str(p.parent.name) + "_" + p.name
            used_names.add(arc_name)
            result.artifacts.append(str(p))
        meaningful_steps = [s for s in steps if s.status != "SKIP"]
        result.success = bool(meaningful_steps) and all(s.status == "PASS" for s in meaningful_steps) and not any(s.status in {"ERROR", "TIMEOUT", "FAIL"} for s in steps)
        if not meaningful_steps:
            result.success = False
        if not result.artifacts:
            result.warnings.append("No .aab, .apk or .ipa artifact was created. A green static scan is not a substitute for an installable build.")
        # Add signature note whenever artifact is present; signature validity is not automatically verified.
        if result.artifacts:
            result.warnings.append("Artifact presence was checked, but package signature, upload-key ownership, store validation and runtime launch were not independently verified.")
        # Package while temp files still exist; artifact content is read directly into the ZIP.
        _package_results(destination_zip, result, report, checklist, workspace)

    return result
