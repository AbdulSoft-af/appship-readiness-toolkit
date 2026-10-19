"""Self-contained, offline, branded HTML readiness reports."""
from __future__ import annotations
from html import escape
from .analyzer import ScanReport
from .policy import POLICY_CHECKED_ON, GOOGLE_TARGET_API_URL, APPLE_REVIEW_URL

SEVERITY_COLORS = {
    "critical": "#be123c", "high": "#dc2626", "medium": "#d97706",
    "low": "#64748b", "info": "#0284c7",
}


def render_html_report(report: ScanReport, extra_notes: list[str] | None = None) -> str:
    findings = []
    for finding in report.findings:
        sev = finding.severity.lower()
        color = SEVERITY_COLORS.get(sev, "#475569")
        findings.append(f"""
        <article class="finding">
          <div class="finding-head"><span class="badge" style="background:{color}">{escape(sev.upper())}</span>
          <span class="rule">{escape(finding.id)}</span><h3>{escape(finding.title)}</h3></div>
          <dl>
            <dt>Platform</dt><dd>{escape(finding.platform)}</dd>
            <dt>File</dt><dd><code>{escape(finding.path)}</code></dd>
            <dt>Category</dt><dd>{escape(finding.category)}</dd>
            <dt>Safe auto-fix</dt><dd>{'Available (review before use)' if finding.auto_fixable else 'Not available'}</dd>
          </dl>
          <p><strong>Finding</strong><br>{escape(finding.detail)}</p>
          <p><strong>Recommended action</strong><br>{escape(finding.recommendation)}</p>
        </article>""")
    if not findings:
        findings.append('<p class="empty">No findings were emitted. This is not proof of approval, security, or correct runtime behavior.</p>')
    notes_html = ""
    if extra_notes:
        notes_html = "<section><h2>Import and scan notes</h2><ul>" + "".join(f"<li>{escape(str(note))}</li>" for note in extra_notes) + "</ul></section>"
    summary = report.summary
    cards = []
    for key in ("critical", "high", "medium", "low", "info"):
        cards.append(f'<div class="metric"><span>{key.upper()}</span><strong style="color:{SEVERITY_COLORS[key]}">{summary.get(key, 0)}</strong></div>')
    score = report.indicative_score
    project = escape(report.project_name)
    stacks = escape(", ".join(report.stacks))
    profile = escape(report.android_app_category)
    generated = escape(report.generated_at)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AppShip Readiness Report — {project}</title>
<style>
:root{{--bg:#f3f6fb;--panel:#fff;--ink:#172033;--muted:#5e6b82;--line:#e1e7f0;--navy:#0b1220;--blue:#2563eb;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 Inter,Segoe UI,Arial,sans-serif}}
header{{background:linear-gradient(125deg,#0b1220,#172d4b);color:#f8fafc;padding:34px max(22px,calc((100% - 1120px)/2)) 30px}}
.brand{{font-weight:800;letter-spacing:.14em;color:#93c5fd;font-size:12px}}h1{{font-size:clamp(24px,4vw,38px);line-height:1.15;margin:10px 0}}header p{{color:#c4d2e6;margin:8px 0}}main{{max-width:1120px;margin:26px auto;padding:0 20px 50px}}
.topgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:18px}}.metric,.panel,.finding{{background:var(--panel);border:1px solid var(--line);border-radius:13px;box-shadow:0 5px 18px #0b122008}}
.metric{{padding:14px 17px}}.metric span{{display:block;font-size:11px;font-weight:800;letter-spacing:.08em;color:var(--muted)}}.metric strong{{font-size:26px;display:block;margin-top:5px}}
.panel{{padding:19px 21px;margin:14px 0}}h2{{font-size:20px;margin:0 0 12px}}.metadata{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;color:var(--muted)}}.metadata strong{{color:var(--ink)}}
.finding{{padding:18px 20px;margin:12px 0}}.finding-head{{display:flex;align-items:center;gap:9px;flex-wrap:wrap}}.badge{{color:white;border-radius:5px;padding:3px 8px;font-size:10px;font-weight:800;letter-spacing:.06em}}.rule{{font:12px ui-monospace,monospace;color:var(--muted)}}h3{{font-size:17px;margin:0}}dl{{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;margin:13px 0}}dt{{font-weight:700;color:var(--muted)}}dd{{margin:0;overflow-wrap:anywhere}}code{{background:#eff4fb;padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}}p{{overflow-wrap:anywhere}}.empty{{background:white;border:1px solid var(--line);padding:18px;border-radius:10px}}
a{{color:#2563eb}}footer{{border-top:1px solid var(--line);padding-top:20px;margin-top:25px;color:var(--muted);font-size:13px}}
@media print{{body{{background:#fff}}header{{padding:22px;color:#111;background:#fff;border-bottom:2px solid #0b1220}}header p{{color:#333}}main{{padding:0;max-width:none}}.metric,.panel,.finding{{box-shadow:none;break-inside:avoid}}}}
</style></head><body>
<header><div class="brand">APPSHIP · BUILD · VERIFY · SHIP</div><h1>Readiness report</h1><p>{project}</p><p>Static preflight • Score {score}/100 — prioritization indicator, not approval probability</p></header>
<main>
<div class="topgrid">{''.join(cards)}</div>
<section class="panel"><h2>Project overview</h2><div class="metadata">
<div><strong>Detected stack(s)</strong><br>{stacks}</div><div><strong>Files scanned</strong><br>{report.files_scanned:,}</div>
<div><strong>Text bytes inspected</strong><br>{report.total_text_bytes:,}</div><div><strong>Android policy profile</strong><br>{profile}</div>
<div><strong>Report generated</strong><br>{generated}</div><div><strong>Policy snapshot checked</strong><br>{POLICY_CHECKED_ON}</div>
</div></section>
<section><h2>Findings ({len(report.findings)})</h2>{''.join(findings)}</section>
{notes_html}
<section class="panel"><h2>Before you publish</h2><p>AppShip performs source-level checks and cannot prove runtime behavior, signing, privacy disclosures, content rights, app review access, or Store acceptance. Review the current official requirements:</p><ul><li><a href="{GOOGLE_TARGET_API_URL}">Google Play target API requirements</a></li><li><a href="{APPLE_REVIEW_URL}">Apple App Review Guidelines</a></li></ul><p>Build and test the exact release artifact on supported devices. This report is an aid for developers, not an official validation certificate.</p></section>
<footer>Generated locally by AppShip Readiness Toolkit. No external service was needed to render this report.</footer>
</main></body></html>'''
