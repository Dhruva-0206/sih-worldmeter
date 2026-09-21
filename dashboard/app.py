"""Minimal local dashboard: trigger scans, browse the latest report.

    uvicorn dashboard.app:app --reload --port 8787

Deliberately plain HTML/JS (no build step) rather than a React app — this is
a local operator tool for the demo, not a product surface, and every extra
build step is one more thing that can break five minutes before a live demo.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.common.config import UnsafeTargetError, load_scan_config  # noqa: E402
from engine.orchestrator import run_multi  # noqa: E402
from report.report_generator import generate_report  # noqa: E402

app = FastAPI(title="World Monitor Security Assessment Dashboard")

CONFIG_DIR = ROOT / "config"
OUTPUT_DIR = ROOT / "output"

_scan_state = {"status": "idle", "detail": "", "findings_count": None}
_scan_lock = threading.Lock()


class ScanRequest(BaseModel):
    configs: list[str]  # filenames under config/, e.g. ["worldmonitor.yaml", "fixture.yaml"]
    sast_only: bool = False
    dast_only: bool = False


def _run_scan_background(config_names: list[str], sast_only: bool, dast_only: bool) -> None:
    with _scan_lock:
        _scan_state.update(status="running", detail="loading configs", findings_count=None)
    try:
        configs = [load_scan_config(CONFIG_DIR / name) for name in config_names]
        with _scan_lock:
            _scan_state["detail"] = f"running pipeline for {len(configs)} target(s)"
        findings = run_multi(configs, sast_only=sast_only, dast_only=dast_only)
        generate_report(findings, OUTPUT_DIR)
        with _scan_lock:
            _scan_state.update(status="done", detail="report written to output/", findings_count=len(findings))
    except Exception as exc:  # surfaced to the dashboard UI, not swallowed
        with _scan_lock:
            _scan_state.update(status="error", detail=str(exc), findings_count=None)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    configs = sorted(p.name for p in CONFIG_DIR.glob("*.yaml"))
    options = "".join(f'<option value="{c}">{c}</option>' for c in configs)
    return f"""<!DOCTYPE html>
<html><head><title>World Monitor Security Assessment</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 720px; margin: 40px auto; color: #1a1a2e; }}
  h1 {{ font-size: 22px; }}
  select, button {{ font-size: 14px; padding: 6px 10px; margin: 4px 4px 4px 0; }}
  #status {{ margin-top: 16px; padding: 10px; border-radius: 4px; background: #f4f5f7; white-space: pre-wrap; }}
  .link-row a {{ margin-right: 12px; }}
</style></head>
<body>
  <h1>World Monitor Security Assessment Framework</h1>
  <p>Select target config(s), choose a mode, and run the pipeline.</p>
  <div>
    <label>Targets:</label><br>
    <select id="configs" multiple size="4">{options}</select>
  </div>
  <div>
    <label><input type="radio" name="mode" value="full" checked> Full (SAST+DAST)</label>
    <label><input type="radio" name="mode" value="sast"> SAST only</label>
    <label><input type="radio" name="mode" value="dast"> DAST only</label>
  </div>
  <button onclick="runScan()">Run Assessment</button>
  <button onclick="pollStatus()">Refresh Status</button>
  <div id="status">idle</div>
  <div class="link-row" style="margin-top:16px;">
    <a href="/report/html" target="_blank">View latest HTML report</a>
    <a href="/report/pdf" target="_blank">Download latest PDF</a>
    <a href="/report/json" target="_blank">Raw JSON</a>
  </div>
<script>
function selectedConfigs() {{
  return Array.from(document.getElementById('configs').selectedOptions).map(o => o.value);
}}
function mode() {{
  return document.querySelector('input[name=mode]:checked').value;
}}
async function runScan() {{
  const configs = selectedConfigs();
  if (!configs.length) {{ alert('Select at least one target config'); return; }}
  const m = mode();
  const body = {{ configs, sast_only: m === 'sast', dast_only: m === 'dast' }};
  await fetch('/api/scan', {{ method: 'POST', headers: {{'Content-Type':'application/json'}}, body: JSON.stringify(body) }});
  pollStatus();
}}
async function pollStatus() {{
  const r = await fetch('/api/scan/status');
  const j = await r.json();
  document.getElementById('status').textContent = JSON.stringify(j, null, 2);
  if (j.status === 'running') setTimeout(pollStatus, 2000);
}}
</script>
</body></html>"""


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> JSONResponse:
    with _scan_lock:
        if _scan_state["status"] == "running":
            raise HTTPException(409, "A scan is already running")
    thread = threading.Thread(target=_run_scan_background, args=(req.configs, req.sast_only, req.dast_only), daemon=True)
    thread.start()
    return JSONResponse({"started": True})


@app.get("/api/scan/status")
def scan_status() -> dict:
    with _scan_lock:
        return dict(_scan_state)


@app.get("/report/html")
def report_html():
    path = OUTPUT_DIR / "security_assessment_report.html"
    if not path.exists():
        raise HTTPException(404, "No report yet — run a scan first")
    return FileResponse(path, media_type="text/html")


@app.get("/report/pdf")
def report_pdf():
    path = OUTPUT_DIR / "security_assessment_report.pdf"
    if not path.exists():
        raise HTTPException(404, "No PDF report yet — run a scan first")
    return FileResponse(path, media_type="application/pdf")


@app.get("/report/json")
def report_json():
    path = OUTPUT_DIR / "security_assessment_report.json"
    if not path.exists():
        raise HTTPException(404, "No report yet — run a scan first")
    return FileResponse(path, media_type="application/json")
