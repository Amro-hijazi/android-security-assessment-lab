"""ASAL Streamlit dashboard.

Run from the project root:
    streamlit run ui/app.py

The UI contains no analysis logic: it calls the same core engine as the CLI
(run_scan), displays ScanResult, and records the analyst's review decisions.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # make the `asal` package importable when run via streamlit

from asal.core.apk_loader import ApkValidationError  # noqa: E402
from asal.core.models import CheckOutcome, Origin, ScanResult, Severity, Status  # noqa: E402
from asal.core.scanner import run_scan  # noqa: E402
from asal.reporting.html_report import numbered_lines, render_html_report, write_html_report  # noqa: E402
from asal.reporting.json_report import load_report, save_report, save_review  # noqa: E402

OUT_ROOT = ROOT / "out"
SEV_ICON = {"critical": "🟥", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}
STATUS_LABEL = {"auto": "🤖 Auto (not reviewed)", "verified": "✅ Verified", "false_positive": "🚫 False positive"}
SEVERITIES = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]

st.set_page_config(page_title="Android Security Assessment Lab", page_icon="🛡️", layout="wide")


# ----------------------------------------------------------------------------- helpers

def safe_name(name: str) -> str:
    stem = Path(name).stem
    return re.sub(r"[^A-Za-z0-9_.-]", "_", stem)[:60] or "app"


def previous_scans() -> list[Path]:
    if not OUT_ROOT.is_dir():
        return []
    return sorted((p.parent for p in OUT_ROOT.glob("*/report.json")), key=lambda p: p.stat().st_mtime, reverse=True)


def run_analysis(upload, include_libs: bool) -> Path | None:
    uploads = OUT_ROOT / "_uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    apk_path = uploads / f"{safe_name(upload.name)}.apk"
    apk_path.write_bytes(upload.getbuffer())
    out_dir = OUT_ROOT / safe_name(upload.name)

    out_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(out_dir / "asal.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    try:
        with st.status("Analyzing APK…", expanded=True) as status:
            st.write("Validating APK, decompiling with APKTool and JADX (this can take 1–3 minutes)…")
            scan = run_scan(apk_path, out_dir, include_libraries=include_libs)
            st.write(f"Found {len(scan.findings)} findings. Writing reports…")
            save_report(scan, out_dir)
            write_html_report(scan, out_dir)
            status.update(label="Analysis complete", state="complete")
        return out_dir
    except ApkValidationError as exc:
        st.error(f"Invalid APK: {exc}")
    except Exception as exc:  # show the error instead of a stack trace
        st.error(f"Analysis failed: {exc}")
        logging.exception("UI analysis failed")
    finally:
        root.removeHandler(handler)
        handler.close()
    return None


def lang_for(file: str) -> str:
    return "xml" if file.endswith(".xml") else "yaml" if file.endswith(".yml") else "java"


def code_block(loc) -> str:
    rows = []
    for n, text, hit in numbered_lines(loc):
        rows.append(f"{(n or ''):>5} {'▶' if hit else ' '} {text}")
    return "\n".join(rows)


# ----------------------------------------------------------------------------- sidebar

with st.sidebar:
    st.title("🛡️ ASAL")
    st.caption("Android Security Assessment Lab · static analysis assistant")
    mode = st.radio("Mode", ["Scan a new APK", "Open a previous scan"], label_visibility="collapsed")

    if mode == "Scan a new APK":
        upload = st.file_uploader("APK file", type=["apk"])
        include_libs = st.checkbox("Also scan third-party libraries", value=False,
                                   help="Off by default to focus on the app's own code")
        if st.button("Run analysis", type="primary", disabled=upload is None, width="stretch"):
            out = run_analysis(upload, include_libs)
            if out:
                st.session_state["out_dir"] = str(out)
    else:
        scans = previous_scans()
        if not scans:
            st.info("No previous scans in the out/ folder yet.")
        else:
            choice = st.selectbox("Scan", scans, format_func=lambda p: p.name)
            if st.button("Open", width="stretch"):
                st.session_state["out_dir"] = str(choice)

    st.divider()
    st.caption("For authorized testing and intentionally vulnerable apps only.")

out_dir = st.session_state.get("out_dir")
if not out_dir or not (Path(out_dir) / "report.json").is_file():
    st.header("Android Security Assessment Lab")
    st.markdown(
        "1. Upload an APK in the sidebar and click **Run analysis**.\n"
        "2. Review each finding: read the evidence, follow **How to verify**, then mark it "
        "**Verified** or **False positive** with notes.\n"
        "3. Export the HTML/JSON report.\n\n"
        "The APK is never installed or executed. Every automated finding starts as **Auto** "
        "until you confirm it."
    )
    st.stop()

out_dir = Path(out_dir)
scan: ScanResult = load_report(out_dir)
app = scan.app

# ----------------------------------------------------------------------------- header

st.title(app.package_name or app.file_name)
st.caption(f"Version {app.version_name} ({app.version_code}) · minSdk {app.min_sdk} · targetSdk {app.target_sdk} · "
           f"SHA-256 `{app.sha256}`")
if scan.partial:
    st.warning("Partial results: some analysis steps did not complete. See warnings below.")
if scan.errors:
    with st.expander(f"Analysis warnings ({len(scan.errors)})"):
        for e in scan.errors:
            st.write(f"- {e}")

sev_app = scan.count_by_severity(Origin.APP)
cols = st.columns(5)
for col, s in zip(cols, SEVERITIES):
    col.metric(f"{SEV_ICON[s]} {s.capitalize()}", sev_app[s])
st.caption("Severity counts for the application's own code.")

status_counts = scan.count_by_status()
n_lib = sum(1 for f in scan.findings if f.origin == Origin.LIBRARY)
c1, c2, c3, c4 = st.columns(4)
c1.metric("✅ Verified", status_counts["verified"])
c2.metric("🤖 Not reviewed", status_counts["auto"])
c3.metric("🚫 False positive", status_counts["false_positive"])
c4.metric("📚 Library findings", n_lib)

tab_findings, tab_coverage, tab_export = st.tabs(["Findings", "Coverage", "Export"])

# ----------------------------------------------------------------------------- findings

with tab_findings:
    f1, f2, f3, f4 = st.columns(4)
    sel_sev = f1.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    sel_status = f2.multiselect("Status", [s.value for s in Status], default=[s.value for s in Status],
                                format_func=lambda v: STATUS_LABEL[v])
    sel_origin = f3.multiselect("Origin", ["app", "library"], default=["app"])
    masvs_all = sorted({f.masvs_category.value for f in scan.findings})
    sel_masvs = f4.multiselect("MASVS", masvs_all, default=masvs_all)

    shown = [f for f in scan.findings
             if f.severity.value in sel_sev and f.status.value in sel_status
             and f.origin.value in sel_origin and f.masvs_category.value in sel_masvs]

    st.dataframe(
        pd.DataFrame([{
            "Severity": f"{SEV_ICON[f.severity.value]} {f.severity.value}" + (" ↑" if f.severity_reason else ""),
            "Finding": f.title,
            "MASVS": f.masvs_category.value,
            "Location": f"{f.locations[0].file}:{f.locations[0].line or ''}",
            "Status": STATUS_LABEL[f.status.value],
        } for f in shown]) if shown else pd.DataFrame(),
        width="stretch", hide_index=True,
    )
    st.caption("↑ = severity raised from context. Expand a finding below for evidence and review.")

    for f in shown:
        label = f"{SEV_ICON[f.severity.value]} {f.severity.value.upper()} · {f.title} · {STATUS_LABEL[f.status.value]}"
        with st.expander(label):
            st.markdown(
                f"`{f.masvs_category.value}` `{f.cwe or 'no CWE'}` `confidence: {f.confidence.value}` "
                f"`{f.origin.value} code` `{f.id}`"
            )
            st.write(f.description)
            if f.severity_reason:
                st.info(f"**Severity raised from {f.base_severity.value} to {f.severity.value}:** {f.severity_reason}")
            a, b = st.columns(2)
            a.markdown(f"**Impact**  \n{f.impact}")
            b.markdown(f"**Remediation**  \n{f.remediation}")

            st.markdown(f"**Evidence** ({len(f.locations)} location{'s' if len(f.locations) > 1 else ''})")
            for loc in f.locations[:10]:
                st.caption(f"{loc.file}:{loc.line or ''}")
                st.code(code_block(loc), language=lang_for(loc.file))
            if len(f.locations) > 10:
                st.caption(f"… {len(f.locations) - 10} more in report.json")

            if f.how_to_verify:
                st.markdown("**How to verify manually**")
                st.code(f.how_to_verify, language="bash")

            with st.form(key=f"review-{f.id}"):
                st.markdown("**Analyst review**")
                options = [s.value for s in Status]
                new_status = st.radio("Status", options, index=options.index(f.status.value),
                                      format_func=lambda v: STATUS_LABEL[v], horizontal=True)
                notes = st.text_area("Verification notes (required for Verified / False positive)",
                                     value=f.verification_notes or "",
                                     placeholder="e.g. adb shell am start -n ... opened the screen without login")
                if st.form_submit_button("Save review"):
                    try:
                        f.set_status(Status(new_status), notes.strip() or None)
                    except ValueError as exc:
                        st.error(str(exc))
                    else:
                        save_review(out_dir, f.id, f.status, f.verification_notes)
                        save_report(scan, out_dir)
                        write_html_report(scan, out_dir)
                        st.rerun()

# ----------------------------------------------------------------------------- coverage

with tab_coverage:
    counts = {o.value: sum(1 for c in scan.checks if c.result == o) for o in CheckOutcome}
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Checks with findings", counts["finding"])
    k2.metric("Passed", counts["passed"])
    k3.metric("Not applicable", counts["not_applicable"])
    k4.metric("Errors", counts["error"])
    st.dataframe(pd.DataFrame([{
        "Check": c.title, "ID": c.check_id, "MASVS": c.masvs_category.value,
        "Result": c.result.value.replace("_", " "), "Details": c.details,
    } for c in scan.checks]), width="stretch", hide_index=True)

# ----------------------------------------------------------------------------- export

with tab_export:
    st.write("Reports include your review decisions and notes.")
    name = safe_name(app.package_name or app.file_name)
    st.download_button("Download HTML report", render_html_report(scan), file_name=f"{name}_report.html",
                       mime="text/html", type="primary")
    st.download_button("Download JSON report", scan.model_dump_json(indent=2), file_name=f"{name}_report.json",
                       mime="application/json")
    st.caption(f"Also saved in {out_dir}")
