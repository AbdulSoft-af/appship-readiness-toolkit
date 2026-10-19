from __future__ import annotations
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path

from appship.analyzer import analyze_files, ScanReport
from appship.project_io import load_zip, load_folder, apply_safe_fixes, create_zip_from_files, _project_prefix, is_sensitive_local_file, is_machine_specific_file
from appship.reports import to_markdown, checklist_markdown
from appship.build_runner import run_build_and_test, content_digest
from appship.ai_assist import ollama_repair_suggestion, apply_unified_diff, extract_unified_diff, ollama_check_connection, ollama_list_models
from appship.user_settings import load_settings, save_settings
from appship.policy import ANDROID_PROFILES, DEFAULT_ANDROID_PROFILE
from appship.html_report import render_html_report
from appship.artifact_verifier import verify_artifact, artifact_report_markdown, artifact_report_html

APP_NAME = "AppShip Readiness Toolkit"
APP_VERSION = "3.1.0"
BG = "#0B1220"
PANEL = "#111C2E"
PANEL2 = "#16243A"
TEXT = "#E8EEF8"
MUTED = "#A7B6CC"
ACCENT = "#70A5FF"
GREEN = "#65D6A6"
YELLOW = "#F5C66D"
RED = "#FF7D86"

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_NAME + "  |  Local-first mobile app preflight")
        self.root.geometry("1280x820")
        self.root.minsize(1040, 680)
        self.root.configure(bg=BG)
        self.project_files = None
        self.project_path = None
        self.android_profile = DEFAULT_ANDROID_PROFILE
        self.profile_labels = {
            "Standard app (API 36)": "standard",
            "Wear OS (API 35)": "wear-os",
            "Automotive OS (API 35)": "automotive",
            "Android TV (API 34)": "android-tv",
            "Android XR (API 34)": "android-xr",
        }
        self.project_name = ""
        self.project_kind = ""
        self.import_notes = []
        self.report: ScanReport | None = None
        self.all_findings = []
        self.staged_files = None  # AI changes exist only in this in-memory review copy.
        self.staged_history = []  # Previous in-memory review copies for one-step-at-a-time rollback.
        self.ai_patch_log = []
        self.last_build_log = ""
        self.last_build_success = False
        self.last_built_digest = None
        self.build_queue = queue.Queue()
        self.ai_settings = load_settings()
        self.artifact_queue = queue.Queue()
        self.queue = queue.Queue()
        self._build_style()
        self._build_ui()

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background="#0F1929", foreground=TEXT, fieldbackground="#0F1929", rowheight=30, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=PANEL2, foreground=TEXT, relief="flat", font=("Segoe UI Semibold", 9))
        style.map("Treeview", background=[("selected", "#25436B")], foreground=[("selected", "#FFFFFF")])
        style.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2, foreground=TEXT, arrowcolor=TEXT)
        style.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG, arrowcolor=TEXT)

    def _button(self, parent, text, command, primary=False, state="normal"):
        b = tk.Button(parent, text=text, command=command, state=state,
                      bg=ACCENT if primary else PANEL2,
                      fg="#08111F" if primary else TEXT,
                      activebackground="#9BC0FF" if primary else "#243854",
                      activeforeground="#08111F" if primary else TEXT,
                      disabledforeground="#66758A", relief="flat", bd=0,
                      padx=14, pady=9, cursor="hand2" if state == "normal" else "arrow",
                      font=("Segoe UI Semibold", 9))
        return b

    def _label(self, parent, text, size=10, color=TEXT, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", PANEL), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kwargs)

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG, padx=22, pady=18)
        header.pack(fill="x")
        title_row = tk.Frame(header, bg=BG)
        title_row.pack(fill="x")
        logo = tk.Canvas(title_row, width=36, height=36, bg=BG, highlightthickness=0)
        logo.pack(side="left", padx=(0, 9))
        logo.create_rectangle(2, 2, 34, 34, fill=PANEL, outline="#273B59", width=1)
        logo.create_polygon(9, 25, 18, 9, 27, 25, 22, 25, 18, 17, 14, 25, fill=ACCENT, outline="")
        logo.create_line(12, 28, 17, 28, 15, 31, fill=GREEN, width=2)
        logo.create_line(20, 28, 25, 28, 27, 31, fill=GREEN, width=2)
        tk.Label(title_row, text="APPSHIP", bg=BG, fg=ACCENT, font=("Segoe UI Semibold", 11)).pack(side="left", padx=(0, 12))
        tk.Label(title_row, text="Readiness Toolkit", bg=BG, fg=TEXT, font=("Segoe UI Semibold", 23)).pack(side="left")
        tk.Label(title_row, text=f" v{APP_VERSION}", bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(8, 0), pady=(10, 0))
        tk.Label(title_row, text="LOCAL-FIRST  •  SOURCE AUDIT  •  RELEASE CHECKLIST", bg=BG, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="right", pady=(10, 0))
        tk.Label(header, text="Find common release blockers before you submit to Google Play or the Apple App Store.", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(5, 0))

        toolbar = tk.Frame(self.root, bg=PANEL, padx=16, pady=13)
        toolbar.pack(fill="x", padx=18)
        self.zip_btn = self._button(toolbar, "Open project ZIP", self.open_zip, True)
        self.zip_btn.pack(side="left", padx=(0, 8))
        self.folder_btn = self._button(toolbar, "Scan project folder", self.open_folder)
        self.folder_btn.pack(side="left", padx=(0, 14))
        self.scan_btn = self._button(toolbar, "Run scan", self.start_scan, state="disabled")
        self.scan_btn.pack(side="left", padx=(0, 8))
        self.export_btn = self._button(toolbar, "Export report", self.export_report, state="disabled")
        self.export_btn.pack(side="left", padx=(0, 8))
        self.package_btn = self._button(toolbar, "Create prepared ZIP", self.create_prepared, state="disabled")
        self.package_btn.pack(side="left")
        self.artifact_btn = self._button(toolbar, "Verify APK/AAB/IPA", self.start_artifact_verify)
        self.artifact_btn.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(toolbar, mode="indeterminate", length=110)
        self.progress.pack(side="right", padx=(12, 4))
        self.profile_var = tk.StringVar(value="Standard app (API 36)")
        self.profile_combo = ttk.Combobox(
            toolbar, textvariable=self.profile_var, state="readonly", width=23,
            values=list(self.profile_labels.keys()),
        )
        self.profile_combo.pack(side="right", padx=(8, 4))
        tk.Label(toolbar, text="Android profile", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="right", padx=(12, 2))
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_changed)

        actions = tk.Frame(self.root, bg=BG, padx=18, pady=2)
        actions.pack(fill="x", pady=(8, 2))
        self.build_btn = self._button(actions, "Build & Test Copy", self.start_build, state="disabled")
        self.build_btn.pack(side="left", padx=(0, 8))
        self.ai_btn = self._button(actions, "AI Repair (Local Ollama)", self.start_ai_repair, state="disabled")
        self.ai_btn.pack(side="left", padx=(0, 8))
        self.undo_btn = self._button(actions, "Undo Last AI Patch", self.undo_last_patch, state="disabled")
        self.undo_btn.pack(side="left", padx=(0, 8))
        self.discard_btn = self._button(actions, "Discard Review Copy", self.discard_review_copy, state="disabled")
        self.discard_btn.pack(side="left", padx=(0, 12))
        tk.Label(actions, text="Build runs trusted scripts on a temporary copy; this is not a full OS sandbox.", bg=BG, fg=YELLOW, font=("Segoe UI", 8)).pack(side="left", padx=(2, 0))

        self.status_var = tk.StringVar(value="Choose a project ZIP or source folder to begin.")
        tk.Label(self.root, textvariable=self.status_var, bg=BG, fg=MUTED, anchor="w", padx=22, pady=8, font=("Segoe UI", 9)).pack(fill="x")

        summary = tk.Frame(self.root, bg=BG, padx=18)
        summary.pack(fill="x", pady=(0, 12))
        self.stat_vars = {}
        for key, label, color in [
            ("score", "INDICATIVE SCORE", ACCENT),
            ("critical", "CRITICAL", RED),
            ("high", "HIGH", RED),
            ("medium", "MEDIUM", YELLOW),
            ("low", "LOW", MUTED),
            ("info", "INFO", GREEN),
        ]:
            tile = tk.Frame(summary, bg=PANEL, padx=15, pady=11, highlightthickness=1, highlightbackground="#1D2D45")
            tile.pack(side="left", fill="x", expand=True, padx=(0, 8))
            tk.Label(tile, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 8)).pack(anchor="w")
            var = tk.StringVar(value="—")
            tk.Label(tile, textvariable=var, bg=PANEL, fg=color, font=("Segoe UI Semibold", 21)).pack(anchor="w", pady=(3, 0))
            self.stat_vars[key] = var

        body = tk.Frame(self.root, bg=BG, padx=18)
        body.pack(fill="both", expand=True, pady=(0, 18))
        left = tk.Frame(body, bg=PANEL, padx=12, pady=12)
        left.pack(side="left", fill="both", expand=True)
        filter_row = tk.Frame(left, bg=PANEL)
        filter_row.pack(fill="x", pady=(0, 10))
        tk.Label(filter_row, text="FINDINGS", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 10)).pack(side="left")
        self.search_var = tk.StringVar()
        search = tk.Entry(filter_row, textvariable=self.search_var, bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat", width=22, font=("Segoe UI", 9))
        search.pack(side="right", padx=(8, 0), ipady=5)
        search.insert(0, "Search findings")
        search.bind("<FocusIn>", lambda e: search.delete(0, "end") if search.get() == "Search findings" else None)
        search.bind("<KeyRelease>", lambda e: self.refresh_tree())
        self.filter_var = tk.StringVar(value="All severities")
        filter_box = ttk.Combobox(filter_row, textvariable=self.filter_var, values=["All severities", "Critical", "High", "Medium", "Low", "Info"], state="readonly", width=15)
        filter_box.pack(side="right")
        filter_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_tree())

        tree_frame = tk.Frame(left, bg=PANEL)
        tree_frame.pack(fill="both", expand=True)
        columns = ("severity", "platform", "title", "file")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for col, heading in [("severity", "SEVERITY"), ("platform", "PLATFORM"), ("title", "CHECK / FINDING"), ("file", "FILE")]:
            self.tree.heading(col, text=heading)
        self.tree.column("severity", width=88, minwidth=76, stretch=False)
        self.tree.column("platform", width=130, minwidth=105, stretch=False)
        self.tree.column("title", width=320, minwidth=200, stretch=True)
        self.tree.column("file", width=210, minwidth=140, stretch=True)
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview, style="Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.tag_configure("critical", foreground=RED)
        self.tree.tag_configure("high", foreground=RED)
        self.tree.tag_configure("medium", foreground=YELLOW)
        self.tree.tag_configure("low", foreground=MUTED)
        self.tree.tag_configure("info", foreground=GREEN)

        right = tk.Frame(body, bg=PANEL, width=370, padx=16, pady=15)
        right.pack(side="right", fill="y", padx=(12, 0))
        right.pack_propagate(False)
        tk.Label(right, text="PROJECT OVERVIEW", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 10)).pack(anchor="w")
        self.project_var = tk.StringVar(value="No project selected")
        tk.Label(right, textvariable=self.project_var, bg=PANEL, fg=ACCENT, wraplength=330, justify="left", font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(8, 8))
        self.meta_var = tk.StringVar(value="Platform: —\nFiles: —\nSource: —")
        tk.Label(right, textvariable=self.meta_var, bg=PANEL, fg=MUTED, justify="left", anchor="w", font=("Segoe UI", 9), wraplength=330).pack(anchor="w")
        tk.Frame(right, height=1, bg="#263852").pack(fill="x", pady=13)
        tk.Label(right, text="SELECTED FINDING", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 10)).pack(anchor="w")
        self.detail_title = tk.StringVar(value="Select a finding from the table")
        tk.Label(right, textvariable=self.detail_title, bg=PANEL, fg=YELLOW, justify="left", anchor="w", wraplength=330, font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(8, 5))
        self.details = tk.Text(right, height=18, bg="#0D1726", fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", padx=11, pady=10, font=("Segoe UI", 9), borderwidth=0)
        self.details.pack(fill="both", expand=True)
        self.details.insert("1.0", "The finding details and recommended next steps will appear here.\n\nThe tool does not execute project code or guarantee store approval.")
        self.details.configure(state="disabled")
        foot = tk.Label(self.root, text="Safety: static scan never executes source. Build & Test runs trusted project scripts on a temporary copy after consent; this is not a full OS sandbox.", bg=BG, fg="#7F91AA", font=("Segoe UI", 8), padx=22, pady=8, anchor="w")
        foot.pack(fill="x")

    def open_zip(self):
        path = filedialog.askopenfilename(title="Choose source project ZIP", filetypes=[("ZIP archive", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        self._load_path(path, "zip")

    def open_folder(self):
        path = filedialog.askdirectory(title="Choose mobile project root folder")
        if not path:
            return
        self._load_path(path, "folder")

    def _load_path(self, path, kind):
        self.status_var.set("Loading source safely…")
        self.root.update_idletasks()
        try:
            files, notes = load_zip(path) if kind == "zip" else load_folder(path)
        except Exception as exc:
            messagebox.showerror("Could not load project", str(exc))
            self.status_var.set("Could not load project. Choose a valid ZIP or source folder.")
            return
        self.project_files = files
        self.staged_files = None
        self.staged_history = []
        self.ai_patch_log = []
        self.undo_btn.configure(state="disabled")
        self.last_build_log = ""
        self.last_build_success = False
        self.last_built_digest = None
        self.project_path = path
        self.project_name = Path(path).stem if kind == "zip" else Path(path).name
        self.project_kind = kind
        self.import_notes = notes
        self.report = None
        self.all_findings = []
        self.project_var.set(self.project_name)
        self.meta_var.set(f"Source: {kind.upper()}\nFiles loaded: {len(files):,}\nLocation: {path}")
        self.status_var.set(f"Loaded {len(files):,} files. Click Run scan to inspect the project.")
        self.scan_btn.configure(state="normal")
        self.build_btn.configure(state="disabled")
        self.ai_btn.configure(state="normal")
        self.discard_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.package_btn.configure(state="disabled")
        self.clear_results()

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for k in self.stat_vars:
            self.stat_vars[k].set("—")
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "Run the scanner to see detailed findings and suggested actions.")
        self.details.configure(state="disabled")
        self.detail_title.set("No finding selected")

    def start_scan(self):
        if not self.project_files:
            return
        self.scan_btn.configure(state="disabled")
        self.zip_btn.configure(state="disabled")
        self.folder_btn.configure(state="disabled")
        self.profile_combo.configure(state="disabled")
        self.build_btn.configure(state="disabled")
        self.ai_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.package_btn.configure(state="disabled")
        self.discard_btn.configure(state="disabled")
        self.undo_btn.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("Scanning source files and release configuration…")
        files = self.staged_files if self.staged_files is not None else self.project_files
        name = self.project_name
        source = "AI review copy (original unchanged)" if self.staged_files is not None else ("ZIP archive" if self.project_kind == "zip" else "local source folder")
        profile = self.android_profile
        thread = threading.Thread(target=self._scan_worker, args=(files, name, source, profile), daemon=True)
        thread.start()
        self.root.after(120, self._poll_queue)

    def _scan_worker(self, files, name, source, profile=DEFAULT_ANDROID_PROFILE):
        try:
            report = analyze_files(files, name, source, profile)
            self.queue.put(("ok", report))
        except Exception as exc:
            self.queue.put(("error", exc))

    def on_profile_changed(self, _event=None):
        selected = self.profile_labels.get(self.profile_var.get(), DEFAULT_ANDROID_PROFILE)
        if selected == self.android_profile:
            return
        self.android_profile = selected
        if self.project_files:
            self.status_var.set("Android policy profile changed; re-running scan with the selected category.")
            self.start_scan()

    def _poll_queue(self):
        try:
            typ, payload = self.queue.get_nowait()
        except queue.Empty:
            self.root.after(120, self._poll_queue)
            return
        self.progress.stop()
        self.scan_btn.configure(state="normal")
        self.zip_btn.configure(state="normal")
        self.folder_btn.configure(state="normal")
        self.profile_combo.configure(state="readonly")
        self.build_btn.configure(state="normal" if self.report else "disabled")
        self.ai_btn.configure(state="normal")
        self.discard_btn.configure(state="normal" if self.staged_files is not None else "disabled")
        self.undo_btn.configure(state="normal" if self.staged_history else "disabled")
        if typ == "error":
            messagebox.showerror("Scan failed", str(payload))
            self.status_var.set("Scan failed. Check the project and try again.")
            return
        self.report = payload
        self.all_findings = list(payload.findings)
        self.build_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        self.package_btn.configure(state="normal")
        self.project_var.set(payload.project_name)
        stage_note = "\nWorking copy: AI review copy (original unchanged)" if self.staged_files is not None else ""
        self.meta_var.set(f"Platforms: {', '.join(payload.stacks)}\nAndroid profile: {payload.android_app_category}\nFiles scanned: {payload.files_scanned:,}\nSource: {payload.project_source}{stage_note}")
        self.stat_vars["score"].set(f"{payload.indicative_score}/100")
        for key in ("critical", "high", "medium", "low", "info"):
            self.stat_vars[key].set(str(payload.summary.get(key, 0)))
        self.refresh_tree()
        notes_count = len(self.import_notes)
        self.status_var.set(f"Scan complete: {payload.summary['total']} findings. {notes_count} import note(s). Score is indicative only, not approval probability.")

    def refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        if not self.report:
            return
        search = self.search_var.get().strip().lower()
        if search == "search findings":
            search = ""
        sev = self.filter_var.get().lower()
        for idx, f in enumerate(self.all_findings):
            if sev != "all severities" and f.severity != sev:
                continue
            needle = " ".join([f.id, f.severity, f.platform, f.title, f.path, f.detail, f.recommendation]).lower()
            if search and search not in needle:
                continue
            self.tree.insert("", "end", iid=str(idx), values=(f.severity.upper(), f.platform, f.title, f.path), tags=(f.severity,))

    def on_select(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        f = self.all_findings[int(selected[0])]
        self.detail_title.set(f"[{f.severity.upper()}] {f.title}")
        body = (
            f"Rule: {f.id}\nPlatform: {f.platform}\nFile: {f.path}\nCategory: {f.category}\n"
            f"Safe auto-fix available: {'Yes' if f.auto_fixable else 'No'}\n\n"
            f"WHAT WAS FOUND\n{f.detail}\n\nRECOMMENDED ACTION\n{f.recommendation}"
        )
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", body)
        self.details.configure(state="disabled")

    def export_report(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(title="Export scan report", defaultextension=".md",
                 initialfile=f"{self.project_name}_appship_report.md",
                 filetypes=[("Markdown report", "*.md"), ("JSON report", "*.json"), ("HTML report", "*.html")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                Path(path).write_text(json.dumps(self.report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            elif path.lower().endswith(".html"):
                Path(path).write_text(render_html_report(self.report, self.import_notes), encoding="utf-8")
            else:
                Path(path).write_text(to_markdown(self.report, self.import_notes), encoding="utf-8")
            self.status_var.set(f"Report exported: {path}")
            messagebox.showinfo("Report exported", f"Saved report to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def start_artifact_verify(self):
        path = filedialog.askopenfilename(
            title="Choose a release artifact to verify",
            filetypes=[("Android / iOS release artifacts", "*.apk *.aab *.ipa"),
                       ("Android APK", "*.apk"), ("Android App Bundle", "*.aab"),
                       ("iOS App archive", "*.ipa"), ("All files", "*.*")],
        )
        if not path:
            return
        self.artifact_btn.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Inspecting release artifact without running or extracting it: {Path(path).name}…")
        threading.Thread(target=self._artifact_verify_worker, args=(path,), daemon=True).start()
        self.root.after(150, self._poll_artifact_queue)

    def _artifact_verify_worker(self, path):
        try:
            self.artifact_queue.put(("ok", verify_artifact(path)))
        except Exception as exc:
            self.artifact_queue.put(("error", exc))

    def _poll_artifact_queue(self):
        try:
            typ, payload = self.artifact_queue.get_nowait()
        except queue.Empty:
            self.root.after(150, self._poll_artifact_queue)
            return
        self.progress.stop()
        self.artifact_btn.configure(state="normal")
        if typ == "error":
            self.status_var.set("Artifact verification could not finish.")
            messagebox.showerror("Artifact verification failed", str(payload), parent=self.root)
            return
        self.status_var.set(f"Artifact verification complete: {payload.artifact_name} — {payload.overall_status}.")
        self._show_artifact_report(payload)

    def _show_artifact_report(self, report):
        win = tk.Toplevel(self.root)
        win.title(f"AppShip — Artifact verification: {report.overall_status}")
        win.geometry("850x660")
        win.minsize(650, 460)
        win.configure(bg=BG)
        header = tk.Frame(win, bg=BG, padx=16, pady=14)
        header.pack(fill="x")
        status_color = GREEN if report.overall_status == "PASS" else RED if report.overall_status == "FAIL" else YELLOW
        tk.Label(header, text=f"{report.artifact_type.upper()} · {report.artifact_name}", bg=BG, fg=TEXT, font=("Segoe UI Semibold", 15)).pack(anchor="w")
        tk.Label(header, text=f"Overall status: {report.overall_status}  |  {report.size_bytes:,} bytes", bg=BG, fg=status_color, font=("Segoe UI Semibold", 10)).pack(anchor="w", pady=(5, 0))
        tk.Label(header, text="Checks package structure and local verifiers where available; does not execute the app or guarantee Store approval.", bg=BG, fg=MUTED, wraplength=790, justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(6, 0))
        body = tk.Frame(win, bg=PANEL, padx=10, pady=10)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        text = tk.Text(body, bg="#0D1726", fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", padx=12, pady=10, font=("Consolas", 9))
        scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("1.0", artifact_report_markdown(report))
        text.configure(state="disabled")
        actions = tk.Frame(win, bg=BG, padx=14, pady=12)
        actions.pack(fill="x")

        def save_report(as_html=False):
            extension = ".html" if as_html else ".md"
            filetypes = [("HTML report", "*.html")] if as_html else [("Markdown report", "*.md")]
            output = filedialog.asksaveasfilename(parent=win, title="Save artifact verification report",
                defaultextension=extension, initialfile=f"{Path(report.artifact_name).stem}_appship_verification{extension}",
                filetypes=filetypes)
            if not output:
                return
            content = artifact_report_html(report) if as_html else artifact_report_markdown(report)
            try:
                Path(output).write_text(content, encoding="utf-8")
                self.status_var.set(f"Artifact verification report exported: {output}")
                messagebox.showinfo("Report exported", f"Saved report to:\n{output}", parent=win)
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc), parent=win)

        self._button(actions, "Save Markdown report", lambda: save_report(False)).pack(side="left", padx=(0, 8))
        self._button(actions, "Save HTML report", lambda: save_report(True), primary=True).pack(side="left")
        self._button(actions, "Close", win.destroy).pack(side="right")

    def start_build(self):
        files = self.staged_files if self.staged_files is not None else self.project_files
        if not files:
            messagebox.showinfo("Choose a project", "Open a source ZIP or folder first.")
            return
        if not self.report:
            messagebox.showinfo("Scan first", "Run Scan before Build & Test so the build bundle includes the current readiness report and platform checklist.")
            return
        consent = messagebox.askyesno(
            "Build safety notice",
            "Build and test commands execute scripts from the selected project on your computer. AppShip uses a temporary working copy and does not modify the original folder, but this is NOT a full operating-system sandbox.\n\nOnly continue with source you trust. Continue?",
            icon="warning",
        )
        if not consent:
            return
        allow_dependencies = messagebox.askyesno(
            "Dependency download permission",
            "Allow package managers to download project dependencies from the internet? This may run package lifecycle scripts.\n\nChoose No to request offline Gradle resolution and skip Flutter Pub/npm dependency installation. A missing Gradle Wrapper distribution may still attempt to download, so this is not strict network isolation.",
            icon="warning",
        )
        output_path = filedialog.asksaveasfilename(
            title="Save Build & Test bundle", defaultextension=".zip",
            initialfile=f"{self.project_name}_appship_build_test.zip",
            filetypes=[("ZIP build report and artifacts", "*.zip")],
        )
        if not output_path:
            return
        self.build_btn.configure(state="disabled")
        self.ai_btn.configure(state="disabled")
        self.scan_btn.configure(state="disabled")
        self.zip_btn.configure(state="disabled")
        self.folder_btn.configure(state="disabled")
        self.profile_combo.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.package_btn.configure(state="disabled")
        self.discard_btn.configure(state="disabled")
        self.undo_btn.configure(state="disabled")
        self.progress.start(12)
        source_label = "AI review copy" if self.staged_files is not None else "original source copy"
        self.status_var.set(f"Running Build & Test on a temporary {source_label}; the original files remain unchanged…")
        files_copy = dict(files)
        report_copy = self.report
        thread = threading.Thread(
            target=self._build_worker,
            args=(files_copy, self.project_name, report_copy, output_path, allow_dependencies),
            daemon=True,
        )
        thread.start()
        self.root.after(200, self._poll_build_queue)

    def _build_worker(self, files, name, report, output_path, allow_dependencies):
        try:
            result = run_build_and_test(
                files=files,
                project_name=name,
                report=report,
                destination_zip=output_path,
                allow_dependency_install=allow_dependencies,
            )
            self.build_queue.put(("ok", result))
        except Exception as exc:
            self.build_queue.put(("error", exc))

    def _poll_build_queue(self):
        try:
            typ, payload = self.build_queue.get_nowait()
        except queue.Empty:
            self.root.after(250, self._poll_build_queue)
            return
        self.progress.stop()
        self.build_btn.configure(state="normal")
        self.ai_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        self.zip_btn.configure(state="normal")
        self.folder_btn.configure(state="normal")
        self.profile_combo.configure(state="readonly")
        self.export_btn.configure(state="normal" if self.report else "disabled")
        self.package_btn.configure(state="normal" if self.report else "disabled")
        self.discard_btn.configure(state="normal" if self.staged_files is not None else "disabled")
        self.undo_btn.configure(state="normal" if self.staged_history else "disabled")
        if typ == "error":
            messagebox.showerror("Build & Test failed to start", str(payload))
            self.status_var.set("Build & Test did not complete. See the error message and try again.")
            return
        result = payload
        self.last_build_log = result.log
        self.last_build_success = result.success
        active_files = self.staged_files if self.staged_files is not None else self.project_files
        if result.success and active_files is not None:
            self.last_built_digest = content_digest(active_files)
        else:
            self.last_built_digest = None
        self.status_var.set(f"Build & Test complete: {result.summary()} Bundle: {result.bundle_path}")
        detail = result.summary() + f"\n\nBundle: {result.bundle_path}\n"
        if result.artifacts:
            detail += "\nArtifacts created (signature still requires verification):\n" + "\n".join(Path(x).name for x in result.artifacts)
        if result.warnings:
            detail += "\n\nNotes:\n- " + "\n- ".join(result.warnings[:10])
        detail += "\n\nUse AI Repair (Local Ollama) to generate a patch proposal from the latest log. Review the diff before applying it to the separate review copy."
        messagebox.showinfo("Build & Test finished", detail)

    def _ask_ai_settings(self):
        """Show local Ollama settings, test the connection, and require an installed model."""
        win = tk.Toplevel(self.root)
        win.title("AppShip — Local AI Settings")
        win.transient(self.root)
        win.grab_set()
        win.geometry("700x500")
        win.minsize(620, 460)
        win.configure(bg=BG)
        result = {"value": None}
        tk.Label(win, text="LOCAL AI REPAIR SETTINGS", bg=BG, fg=ACCENT,
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", padx=18, pady=(16, 5))
        tk.Label(win, text="AppShip sends selected, filtered source excerpts only to a loopback Ollama service. Remote AI URLs are blocked.",
                 bg=BG, fg=MUTED, wraplength=660, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(0, 14))
        form = tk.Frame(win, bg=PANEL, padx=16, pady=16)
        form.pack(fill="x", padx=18)
        tk.Label(form, text="Ollama local endpoint", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 9)).grid(row=0, column=0, sticky="w", pady=(0, 5))
        url_var = tk.StringVar(value=self.ai_settings.get("ollama_url", "http://127.0.0.1:11434"))
        url_entry = tk.Entry(form, textvariable=url_var, bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10))
        url_entry.grid(row=1, column=0, sticky="ew", ipady=6)
        tk.Label(form, text="Installed model", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 9)).grid(row=2, column=0, sticky="w", pady=(13, 5))
        model_var = tk.StringVar(value=self.ai_settings.get("ollama_model", "qwen2.5-coder:7b"))
        model_box = ttk.Combobox(form, textvariable=model_var, values=[], state="normal")
        model_box.grid(row=3, column=0, sticky="ew", ipady=3)
        tk.Label(form, text="Repair request timeout (seconds, 10–600)", bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 9)).grid(row=4, column=0, sticky="w", pady=(13, 5))
        timeout_var = tk.StringVar(value=str(self.ai_settings.get("ai_timeout_seconds", 180)))
        timeout_box = ttk.Spinbox(form, from_=10, to=600, increment=30, textvariable=timeout_var)
        timeout_box.grid(row=5, column=0, sticky="ew", ipady=3)
        form.columnconfigure(0, weight=1)
        status_var = tk.StringVar(value="1. Install Ollama.  2. Start its service.  3. Download a coding model.")
        status_label = tk.Label(win, textvariable=status_var, bg=BG, fg=YELLOW, wraplength=660, justify="left", font=("Segoe UI", 9))
        status_label.pack(anchor="w", padx=20, pady=(10, 4))
        tk.Label(win, text="Install guide: https://ollama.com/download  •  Example command: ollama pull qwen2.5-coder:7b",
                 bg=BG, fg=MUTED, wraplength=660, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=20, pady=(0, 10))
        buttons = tk.Frame(win, bg=BG, padx=18, pady=12)
        buttons.pack(fill="x", side="bottom")

        def refresh_models(show_message=True):
            base = url_var.get().strip()
            try:
                info = ollama_check_connection(base, timeout_seconds=5)
                models = ollama_list_models(base, timeout_seconds=8)
                model_box.configure(values=models)
                current = model_var.get().strip()
                if models and current not in models:
                    model_var.set(models[0])
                if models:
                    status_var.set(f"Connected to Ollama {info['version']} · {len(models)} installed model(s).")
                    status_label.configure(fg=GREEN)
                    if show_message:
                        messagebox.showinfo("Ollama connected", f"Ollama {info['version']} is responding.\n\nInstalled models:\n" + "\n".join(models), parent=win)
                else:
                    status_var.set(f"Ollama {info['version']} is running, but no model is installed. Run: ollama pull qwen2.5-coder:7b")
                    status_label.configure(fg=YELLOW)
                    if show_message:
                        messagebox.showwarning("No AI model installed", status_var.get(), parent=win)
                return models
            except Exception as exc:
                status_var.set(str(exc))
                status_label.configure(fg=RED)
                if show_message:
                    messagebox.showerror("Ollama connection failed", str(exc), parent=win)
                return None

        test_button = self._button(buttons, "Test + Refresh Models", lambda: refresh_models(True))
        test_button.pack(side="left", padx=(0, 8))

        continue_button = None

        def begin_model_pull():
            model = model_var.get().strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}", model):
                messagebox.showwarning("Invalid model name", "Use a valid Ollama model name, for example qwen2.5-coder:7b.", parent=win)
                return
            ollama_exe = shutil.which("ollama")
            if not ollama_exe:
                messagebox.showerror("Ollama CLI not found", "Install Ollama from https://ollama.com/download, close and reopen AppShip, then retry. You can also run `ollama pull " + model + "` in a terminal.", parent=win)
                return
            if not messagebox.askyesno("Download local AI model", f"Download '{model}' from the Ollama model registry?\n\nThis uses an internet connection and can require several gigabytes of disk space. The model will be stored locally by Ollama.", icon="warning", parent=win):
                return
            test_button.configure(state="disabled")
            pull_button.configure(state="disabled")
            continue_button.configure(state="disabled")
            status_var.set(f"Downloading Ollama model '{model}'… this can take time depending on model size and connection.")
            status_label.configure(fg=YELLOW)
            result_queue = queue.Queue()

            def pull_worker():
                try:
                    completed = subprocess.run(
                        [ollama_exe, "pull", model], stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                        timeout=3600, shell=False, check=False,
                    )
                    result_queue.put(("done", completed.returncode, completed.stdout[-8000:]))
                except subprocess.TimeoutExpired as exc:
                    output = exc.stdout or ""
                    if isinstance(output, bytes):
                        output = output.decode("utf-8", "replace")
                    result_queue.put(("error", "Model download timed out after 60 minutes.\n" + str(output)[-4000:]))
                except OSError as exc:
                    result_queue.put(("error", f"Could not start Ollama model download: {exc}"))

            def poll_pull():
                try:
                    item = result_queue.get_nowait()
                except queue.Empty:
                    if win.winfo_exists():
                        win.after(300, poll_pull)
                    return
                test_button.configure(state="normal")
                pull_button.configure(state="normal")
                continue_button.configure(state="normal")
                if item[0] == "error":
                    status_var.set(str(item[1]))
                    status_label.configure(fg=RED)
                    messagebox.showerror("Model download failed", str(item[1]), parent=win)
                    return
                _, return_code, output = item
                if return_code != 0:
                    detail = f"`ollama pull {model}` failed (exit {return_code}).\n{output[-3500:]}"
                    status_var.set(detail[-800:])
                    status_label.configure(fg=RED)
                    messagebox.showerror("Model download failed", detail, parent=win)
                    return
                models = refresh_models(False)
                if models is not None and model in models:
                    status_var.set(f"Model '{model}' downloaded and available. You can continue to AI Repair.")
                    status_label.configure(fg=GREEN)
                    messagebox.showinfo("Model ready", f"The model '{model}' is installed locally and ready for AppShip AI Repair.", parent=win)
                else:
                    status_var.set("Download command completed, but the model was not returned by Ollama. Refresh models and check the Ollama logs.")
                    status_label.configure(fg=YELLOW)

            threading.Thread(target=pull_worker, daemon=True).start()
            win.after(300, poll_pull)

        pull_button = self._button(buttons, "Download selected model", begin_model_pull)
        pull_button.pack(side="left", padx=(0, 8))

        def continue_repair():
            base = url_var.get().strip()
            model = model_var.get().strip()
            if not model:
                messagebox.showwarning("Model required", "Choose an installed Ollama model or enter a model after downloading it.", parent=win)
                return
            models = refresh_models(False)
            if models is None:
                return
            # Refresh may select the first available model when the saved default is absent.
            model = model_var.get().strip()
            if model not in models:
                messagebox.showwarning("Model not installed", f"The selected model '{model}' is not installed locally. Run this in a terminal:\n\nollama pull {model}\n\nThen click Test + Refresh Models.", parent=win)
                return
            try:
                timeout_seconds = max(10, min(int(timeout_var.get().strip()), 600))
            except (ValueError, AttributeError):
                messagebox.showwarning("Invalid timeout", "Enter a whole number from 10 to 600 seconds.", parent=win)
                return
            self.ai_settings = {"ollama_url": base, "ollama_model": model,
                                "ai_timeout_seconds": timeout_seconds}
            try:
                save_settings(self.ai_settings)
            except OSError as exc:
                messagebox.showwarning("Settings not saved", f"Settings will be used this session, but could not be saved:\n{exc}", parent=win)
            result["value"] = (base, model)
            win.destroy()

        continue_button = self._button(buttons, "Continue to AI Repair", continue_repair, primary=True)
        continue_button.pack(side="left", padx=(0, 8))
        self._button(buttons, "Cancel", win.destroy).pack(side="right")
        url_entry.focus_set()
        self.root.wait_window(win)
        return result["value"]

    def start_ai_repair(self):
        active_files = self.staged_files if self.staged_files is not None else self.project_files
        if not active_files:
            messagebox.showinfo("Choose a project", "Open a source ZIP or folder first.")
            return
        settings = self._ask_ai_settings()
        if not settings:
            return
        base_url, model = settings
        findings = []
        if self.report:
            findings = [f"[{f.severity.upper()}] {f.id} {f.title}: {f.detail} Recommended action: {f.recommendation}" for f in self.report.findings[:25]]
        log = self.last_build_log or "No Build & Test log is available yet. Diagnose the static findings and likely build blockers from the source snippets. Do not invent compiler errors."
        if self.last_build_log and self.last_build_success:
            log = "The previous build/test run did not report a failing step. Review the scanner findings for high-value improvements without changing unrelated code.\n" + log
        consent = messagebox.askyesno(
            "Local AI privacy check",
            f"AppShip will send selected source excerpts and the filtered build log only to local Ollama at {base_url}. It will not send them to a remote AI API.\n\nModel: {model}\nModel output is untrusted; any patch is reviewed and applied only to an in-memory review copy, never to original files. Continue?"
        )
        if not consent:
            return
        self.ai_btn.configure(state="disabled")
        self.build_btn.configure(state="disabled")
        self.scan_btn.configure(state="disabled")
        self.zip_btn.configure(state="disabled")
        self.folder_btn.configure(state="disabled")
        self.profile_combo.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.package_btn.configure(state="disabled")
        self.discard_btn.configure(state="disabled")
        self.undo_btn.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Asking local Ollama model {model} for a conservative diagnosis and patch proposal…")
        files_copy = dict(active_files)
        thread = threading.Thread(target=self._ai_worker, args=(log, files_copy, model, findings, base_url), daemon=True)
        thread.start()
        self.root.after(200, self._poll_ai_queue)

    def _ai_worker(self, log, files, model, findings, base_url="http://127.0.0.1:11434"):
        try:
            response = ollama_repair_suggestion(log=log, files=files, model=model, base_url=base_url, findings=findings, timeout_seconds=int(self.ai_settings.get("ai_timeout_seconds", 180)))
            self.build_queue.put(("ai-ok", response))
        except Exception as exc:
            self.build_queue.put(("ai-error", exc))

    def _poll_ai_queue(self):
        try:
            typ, payload = self.build_queue.get_nowait()
        except queue.Empty:
            self.root.after(250, self._poll_ai_queue)
            return
        self.progress.stop()
        self.ai_btn.configure(state="normal")
        self.build_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        self.zip_btn.configure(state="normal")
        self.folder_btn.configure(state="normal")
        self.profile_combo.configure(state="readonly")
        self.export_btn.configure(state="normal" if self.report else "disabled")
        self.package_btn.configure(state="normal" if self.report else "disabled")
        self.discard_btn.configure(state="normal" if self.staged_files is not None else "disabled")
        self.undo_btn.configure(state="normal" if self.staged_history else "disabled")
        if typ == "ai-error":
            messagebox.showerror("Local AI repair failed", str(payload) + "\n\nInstall Ollama from https://ollama.com/download, start it, then run `ollama pull qwen2.5-coder:7b` and retry.")
            self.status_var.set("Local AI repair could not connect or generate a proposal.")
            return
        self._show_ai_proposal(payload)

    def _show_ai_proposal(self, response):
        win = tk.Toplevel(self.root)
        win.title("AppShip — Local AI Repair Proposal")
        win.transient(self.root)
        win.grab_set()
        win.geometry("940x680")
        win.minsize(760, 500)
        win.configure(bg=BG)
        tk.Label(win, text="AI REPAIR PROPOSAL", bg=BG, fg=ACCENT, font=("Segoe UI Semibold", 13)).pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(win, text="Review the explanation and diff carefully. Changes stay in memory until you create a separate prepared ZIP.", bg=BG, fg=YELLOW, wraplength=900, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 10))
        body = tk.Text(win, bg="#0D1726", fg=TEXT, insertbackground=TEXT, relief="flat", wrap="none", padx=12, pady=10, font=("Consolas", 9), undo=False)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        body.insert("1.0", response)
        body.configure(state="disabled")
        buttons = tk.Frame(win, bg=BG, padx=16, pady=12)
        buttons.pack(fill="x")
        def save_proposal():
            path = filedialog.asksaveasfilename(parent=win, title="Save AI proposal", defaultextension=".md", initialfile=f"{self.project_name}_ai_repair_proposal.md", filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
            if path:
                try:
                    Path(path).write_text(response, encoding="utf-8")
                    messagebox.showinfo("Saved", f"AI proposal saved to:\n{path}", parent=win)
                except OSError as exc:
                    messagebox.showerror("Save failed", str(exc), parent=win)
        def apply_proposal(auto_rebuild=False):
            if not messagebox.askyesno("Apply to review copy", "Apply this untrusted AI diff to a separate in-memory review copy? The original source will not change. Only existing text source/config files are allowed.", icon="warning", parent=win):
                return
            try:
                patch = extract_unified_diff(response)
                base_files = self.staged_files if self.staged_files is not None else self.project_files
                patched, changes = apply_unified_diff(base_files, patch)
                self.staged_history.append((dict(base_files), list(self.ai_patch_log)))
                self.staged_files = patched
                self.ai_patch_log.extend(changes)
                self.last_built_digest = None
                self.last_build_success = False
                self.report = analyze_files(patched, self.project_name, "AI review copy (original unchanged)", self.android_profile)
                self.all_findings = list(self.report.findings)
                self.discard_btn.configure(state="normal")
                self.undo_btn.configure(state="normal")
                self.export_btn.configure(state="normal")
                self.package_btn.configure(state="normal")
                self.project_var.set(self.project_name + " — AI review copy")
                self.meta_var.set(f"Platforms: {', '.join(self.report.stacks)}\nAndroid profile: {self.report.android_app_category}\nFiles scanned: {self.report.files_scanned:,}\nSource: AI review copy\nOriginal source remains unchanged.")
                self.stat_vars["score"].set(f"{self.report.indicative_score}/100")
                for key in ("critical", "high", "medium", "low", "info"):
                    self.stat_vars[key].set(str(self.report.summary.get(key, 0)))
                self.refresh_tree()
                self.status_var.set("AI diff applied to an in-memory review copy. Run Build & Test Copy, then rescan and review the diff.")
                messagebox.showinfo("Patch staged for review", "\n".join(changes) + "\n\nNo original project file was changed." + ("\n\nBuild & Test will start next; confirm the build options." if auto_rebuild else ""), parent=win)
                win.destroy()
                if auto_rebuild:
                    self.root.after(200, self.start_build)
            except Exception as exc:
                messagebox.showerror("Patch was not applied", str(exc), parent=win)
        self._button(buttons, "Save proposal", save_proposal).pack(side="left", padx=(0, 8))
        self._button(buttons, "Apply to review copy", apply_proposal).pack(side="left", padx=(0, 8))
        self._button(buttons, "Apply + Build & Test", lambda: apply_proposal(auto_rebuild=True), primary=True).pack(side="left", padx=(0, 8))
        self._button(buttons, "Close", win.destroy).pack(side="right")

    def undo_last_patch(self):
        if not self.staged_history:
            return
        if not messagebox.askyesno(
            "Undo last AI patch",
            "Restore the in-memory review copy from immediately before the most recent AI patch? The original source folder remains unchanged. You should re-scan and re-run Build & Test after undoing.",
            icon="warning",
        ):
            return
        previous_files, previous_log = self.staged_history.pop()
        self.ai_patch_log = previous_log
        if self.project_files is not None and previous_files == self.project_files:
            self.staged_files = None
            source_label = "original source copy"
        else:
            self.staged_files = previous_files
            source_label = "AI review copy (original unchanged)"
        active_files = self.staged_files if self.staged_files is not None else self.project_files
        if active_files is None:
            return
        self.last_build_success = False
        self.last_built_digest = None
        self.report = analyze_files(active_files, self.project_name, source_label, self.android_profile)
        self.all_findings = list(self.report.findings)
        self.project_var.set(self.project_name if self.staged_files is None else self.project_name + " — AI review copy")
        self.meta_var.set(
            f"Platforms: {', '.join(self.report.stacks)}\nAndroid profile: {self.report.android_app_category}\nFiles scanned: {self.report.files_scanned:,}\n"
            + f"Source: {source_label}\nOriginal source remains unchanged."
        )
        self.stat_vars["score"].set(f"{self.report.indicative_score}/100")
        for key in ("critical", "high", "medium", "low", "info"):
            self.stat_vars[key].set(str(self.report.summary.get(key, 0)))
        self.refresh_tree()
        self.discard_btn.configure(state="normal" if self.staged_files is not None else "disabled")
        self.undo_btn.configure(state="normal" if self.staged_history else "disabled")
        self.export_btn.configure(state="normal")
        self.package_btn.configure(state="normal")
        self.status_var.set("Last AI patch was undone in memory. Re-scan and re-run Build & Test before preparing a release ZIP.")

    def discard_review_copy(self):
        if self.staged_files is None:
            return
        if not messagebox.askyesno("Discard AI review copy", "Discard all staged AI changes and return to the original loaded source copy? No disk files will be changed."):
            return
        self.staged_files = None
        self.staged_history = []
        self.ai_patch_log = []
        self.undo_btn.configure(state="disabled")
        self.last_built_digest = None
        self.last_build_success = False
        self.report = analyze_files(self.project_files, self.project_name, "original source copy", self.android_profile)
        self.all_findings = list(self.report.findings)
        self.discard_btn.configure(state="disabled")
        self.project_var.set(self.project_name)
        self.meta_var.set(f"Platforms: {', '.join(self.report.stacks)}\nFiles scanned: {self.report.files_scanned:,}\nSource: original loaded copy\nOriginal files on disk were never modified.")
        self.stat_vars["score"].set(f"{self.report.indicative_score}/100")
        for key in ("critical", "high", "medium", "low", "info"):
            self.stat_vars[key].set(str(self.report.summary.get(key, 0)))
        self.refresh_tree()
        self.status_var.set("AI review copy discarded. Original loaded source is active again.")

    def create_prepared(self):
        working_files = self.staged_files if self.staged_files is not None else self.project_files
        if not self.report or not working_files:
            return
        path = filedialog.asksaveasfilename(title="Save prepared source bundle", defaultextension=".zip",
                 initialfile=f"{self.project_name}_appship_prepared.zip", filetypes=[("ZIP archive", "*.zip")])
        if not path:
            return
        try:
            package_source = dict(working_files)
            local_only_paths = [
                path_name for path_name, content in package_source.items()
                if is_sensitive_local_file(path_name, content) or is_machine_specific_file(path_name)
            ]
            excluded_paths = []
            if local_only_paths:
                choice = messagebox.askyesnocancel(
                    "Local-only / signing files detected",
                    "These files appear to be machine-specific, local-secret, or signing material:\n\n"
                    + "\n".join(local_only_paths[:25])
                    + ("\n… and more" if len(local_only_paths) > 25 else "")
                    + "\n\nYes = exclude these files from the ZIP (recommended).\nNo = keep them in the ZIP (not recommended for sharing).\nCancel = stop creating the bundle.",
                    icon="warning",
                )
                if choice is None:
                    return
                if choice:
                    excluded_paths = local_only_paths
                    package_source = {k: v for k, v in package_source.items() if k not in set(local_only_paths)}
            source_report = analyze_files(package_source, self.project_name, "sanitized prepared source copy", self.android_profile)
            if any(f.id == "SEC-001" for f in source_report.findings):
                proceed = messagebox.askyesno(
                    "Possible hard-coded credentials detected",
                    "The remaining project copy still contains one or more possible hard-coded secrets. This ZIP may expose them. Remove/rotate real credentials or verify the finding is a false positive before sharing. Continue anyway?",
                    icon="warning",
                )
                if not proceed:
                    return
            active_digest = content_digest(working_files)
            if self.staged_files is not None and self.last_built_digest != active_digest:
                proceed = messagebox.askyesno(
                    "Review copy has not been build-verified",
                    "The current AI review copy has not passed Build & Test since its latest change. Create the source bundle anyway?\n\nRecommended: run Build & Test Copy first.",
                    icon="warning",
                )
                if not proceed:
                    return
            patched, changes = apply_safe_fixes(package_source)
            source_label = "prepared source copy"
            updated_report = analyze_files(patched, self.project_name, source_label, self.android_profile)
            prefix = _project_prefix(patched)
            additions = {
                prefix + "APPSTORE_PLAYSTORE_CHECKLIST.md": checklist_markdown(updated_report.stacks, updated_report.android_app_category).encode("utf-8"),
                prefix + "APPSHIP_READINESS_REPORT.md": to_markdown(updated_report, self.import_notes + changes + ([f"Excluded local-only files from prepared ZIP: {p}" for p in excluded_paths])).encode("utf-8"),
                prefix + "appship_readiness_report.json": json.dumps(updated_report.to_dict(), indent=2, ensure_ascii=False).encode("utf-8"),
                prefix + "APPSHIP_SAFE_FIX_LOG.txt": ("AppShip safe-fix log\n\n" + "\n".join("- " + c for c in changes) + "\n\nOnly listed deterministic fixes were applied. Other source findings require review.\n").encode("utf-8"),
            }
            if excluded_paths:
                additions[prefix + "APPSHIP_EXCLUDED_LOCAL_FILES.txt"] = ("The following local-only/machine-specific files were omitted from this source ZIP by choice:\n\n" + "\n".join("- " + x for x in excluded_paths) + "\n\nConfigure these values on your own trusted build machine. Never commit or share signing credentials.\n").encode("utf-8")
            if self.ai_patch_log:
                additions[prefix + "APPSHIP_AI_REVIEW_LOG.md"] = ("# AI review-copy changes\n\n" + "\n".join("- " + c for c in self.ai_patch_log) + "\n\nAI-generated changes are not trusted until the exact packaged source passes build/test and human review. The original source folder was never modified.\n").encode("utf-8")
            create_zip_from_files(patched, path, additions)
            safe_fix_count = len([c for c in changes if c.startswith('Added android:') or c.startswith('Added a conservative')])
            self.status_var.set(f"Prepared ZIP created. Limited safe fixes: {safe_fix_count}; local-only files excluded: {len(excluded_paths)}.")
            messagebox.showinfo(
                "Prepared ZIP created",
                "The ZIP includes the prepared source, readiness report, Store checklist and fix log.\n\n"
                + ("Local-only files were excluded: " + str(len(excluded_paths)) + ".\n\n" if excluded_paths else "")
                + ("Safe auto-fixes were applied, so this ZIP may differ from the last tested copy.\n\n" if safe_fix_count else "")
                + "Open and scan this exact ZIP, then run Build & Test again before upload. Artifact generation is not proof of correct signing or Store approval."
            )
        except Exception as exc:
            messagebox.showerror("Could not create prepared ZIP", str(exc))


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
