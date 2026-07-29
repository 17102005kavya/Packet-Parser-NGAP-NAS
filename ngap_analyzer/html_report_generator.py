"""
HTML Report Generator for NGAP / NAS Wireshark Diagnostic Analyzer.
Generates standalone, self-contained interactive HTML diagnostic reports with embedded styling and JavaScript.
"""

import json
from typing import Dict, Any
from .models import DiagnosticReport


class HTMLReportGenerator:
    """
    Renders a self-contained, interactive HTML report with glassmorphism styling and sequence diagrams.
    """

    def generate_html_report(self, report: DiagnosticReport) -> str:
        report_data = report.to_dict()
        report_json_str = json.dumps(report_data)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NGAP/NAS Diagnostic Report - {report.pcap_file}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #070a12;
            --bg-surface: #0f1629;
            --card-bg: rgba(19, 29, 53, 0.75);
            --card-hover: rgba(28, 42, 74, 0.9);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --indigo: #6366f1;
            --emerald: #10b981;
            --rose: #f43f5e;
            --amber: #f59e0b;
            --cyan: #06b6d4;
            --font-ui: 'Outfit', sans-serif;
            --font-code: 'JetBrains Mono', monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-dark);
            background-image: radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                              radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.1) 0px, transparent 50%);
            color: var(--text-main);
            font-family: var(--font-ui);
            padding: 2rem;
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 1.5rem; }}
        .header {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(16px);
            padding: 1.5rem 2rem;
            border-radius: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; background: linear-gradient(135deg, #fff, #cbd5e1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header-sub {{ font-size: 0.85rem; color: var(--text-muted); }}
        
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }}
        .mcard {{ background: var(--card-bg); border: 1px solid var(--card-border); padding: 1.25rem; border-radius: 14px; position: relative; overflow: hidden; }}
        .mcard::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }}
        .mblue::before {{ background: var(--indigo); }}
        .mcyan::before {{ background: var(--cyan); }}
        .mred::before {{ background: var(--rose); }}
        .mamber::before {{ background: var(--amber); }}
        .mval {{ font-size: 2rem; font-weight: 700; font-family: var(--font-code); }}
        .mlbl {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}

        .table-wrapper {{ width: 100%; overflow-x: auto; background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 16px; backdrop-filter: blur(16px); }}
        .formal-table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem; }}
        .formal-table th {{ background: rgba(15, 22, 41, 0.85); color: var(--text-muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; padding: 1rem 1.2rem; border-bottom: 1px solid var(--card-border); white-space: nowrap; }}
        .formal-table td {{ padding: 1rem 1.2rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); vertical-align: middle; }}
        .formal-table tbody tr {{ transition: all 0.2s ease; cursor: pointer; }}
        .formal-table tbody tr:hover {{ background: var(--card-hover); }}
        .formal-table tbody tr:last-child td {{ border-bottom: none; }}
        .table-row-failed {{ border-left: 4px solid var(--rose); }}
        .table-row-incomplete {{ border-left: 4px solid var(--amber); }}
        .table-row-success {{ border-left: 4px solid var(--emerald); }}

        .badge {{ font-family: var(--font-code); font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 6px; }}
        .badge-ran {{ background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3); }}
        .badge-amf {{ background: rgba(6, 182, 212, 0.15); color: #67e8f9; border: 1px solid rgba(6, 182, 212, 0.3); }}
        .pill {{ font-size: 0.75rem; font-weight: 600; padding: 0.25rem 0.65rem; border-radius: 20px; }}
        .pill-success {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .pill-failed {{ background: rgba(244, 63, 94, 0.2); color: #fca5a5; border: 1px solid rgba(244, 63, 94, 0.4); }}
        .pill-incomplete {{ background: rgba(245, 158, 11, 0.2); color: #fde047; border: 1px solid rgba(245, 158, 11, 0.4); }}

        .modal-overlay {{ position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; justify-content: center; align-items: center; padding: 2rem; z-index: 1000; }}
        .modal-overlay.hidden {{ display: none; }}
        .modal-box {{ background: var(--bg-surface); border: 1px solid var(--card-border); border-radius: 18px; width: 100%; max-width: 850px; max-height: 85vh; display: flex; flex-direction: column; overflow: hidden; }}
        .modal-hdr {{ padding: 1.25rem; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center; }}
        .modal-body {{ padding: 1.5rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }}
        .close-btn {{ background: none; border: none; color: var(--text-muted); font-size: 1.8rem; cursor: pointer; }}
        
        .seq-row {{ display: grid; grid-template-columns: 110px 1fr; gap: 1rem; align-items: center; font-family: var(--font-code); font-size: 0.82rem; padding: 0.4rem 0; }}
        .seq-frame {{ display: flex; flex-direction: column; gap: 0.2rem; line-height: 1.3; }}
        .frame-num {{ font-weight: 600; color: var(--text-main); font-size: 0.78rem; white-space: nowrap; }}
        .frame-ts {{ font-size: 0.68rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .seq-msg {{ background: rgba(255,255,255,0.04); border: 1px solid var(--card-border); border-radius: 8px; padding: 0.6rem 0.9rem; display: flex; justify-content: space-between; align-items: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <h1>📡 NGAP / NAS 5G Diagnostic Report</h1>
                <div class="header-sub">Standalone Diagnostic Export for: <strong>{report.pcap_file}</strong></div>
            </div>
            <div>
                <span class="badge badge-ran">Generated via Antigravity Diagnostic Engine</span>
            </div>
        </header>

        <section class="metrics-grid">
            <div class="mcard mblue">
                <div class="mlbl">Total Frames</div>
                <div class="mval">{report.total_frames_analyzed}</div>
            </div>
            <div class="mcard mcyan">
                <div class="mlbl">Identified UEs</div>
                <div class="mval">{len(report.ue_contexts)}</div>
            </div>
            <div class="mcard mred">
                <div class="mlbl">Explicit Failures</div>
                <div class="mval" id="cnt-failed">0</div>
            </div>
            <div class="mcard mamber">
                <div class="mlbl">Incomplete</div>
                <div class="mval" id="cnt-inc">0</div>
            </div>
        </section>

        <main id="ue-container">
            <div class="table-wrapper">
                <table class="formal-table">
                    <thead>
                        <tr>
                            <th>Outcome Status</th>
                            <th>UE Context</th>
                            <th>NGAP Identifiers</th>
                            <th>Network Endpoints</th>
                            <th>Procedures & Diagnostics</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="table-body"></tbody>
                </table>
            </div>
        </main>
    </div>

    <div id="modal" class="modal-overlay hidden">
        <div class="modal-box">
            <div class="modal-hdr">
                <h3 id="modal-title">UE Context Signalling Flow</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div id="modal-body" class="modal-body"></div>
        </div>
    </div>

    <script>
        const reportData = {report_json_str};

        document.addEventListener('DOMContentLoaded', () => {{
            renderDashboard();
        }});

        function renderDashboard() {{
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';

            let failed = 0;
            let inc = 0;

            (reportData.ue_contexts || []).forEach(ue => {{
                const hasFail = (ue.explicit_failures && ue.explicit_failures.length > 0);
                const hasInc = (ue.incomplete_procedures && ue.incomplete_procedures.length > 0);

                if (hasFail) failed++;
                else if (hasInc) inc++;

                let pillCls = 'pill-success';
                let pillTxt = 'Completed 🟢';
                let rowCls = 'table-row-success';
                if (hasFail) {{ pillCls = 'pill-failed'; pillTxt = 'Explicit Failure 🔴'; rowCls = 'table-row-failed'; }}
                else if (hasInc) {{ pillCls = 'pill-incomplete'; pillTxt = 'Incomplete 🟡'; rowCls = 'table-row-incomplete'; }}

                const tr = document.createElement('tr');
                tr.className = rowCls;

                const ranStr = ue.ran_ue_ngap_id !== null ? `RAN ID: ${{ue.ran_ue_ngap_id}}` : 'RAN ID: (none)';
                const amfStr = ue.amf_ue_ngap_id !== null ? `AMF ID: ${{ue.amf_ue_ngap_id}}` : 'AMF ID: (none)';
                
                let procsHtml = (ue.procedures || []).map(p => {{
                    const infTag = p.confidence === 'INFERRED' ? ' 🔍' : '';
                    return `<span class="badge" style="background:rgba(255,255,255,0.06);">${{p.name}}: ${{p.status}}${{infTag}}</span>`;
                }}).join(' ');
                let diagSummary = '';
                if (hasFail) {{
                    diagSummary += `<div style="color:#fca5a5; font-size:0.8rem; margin-top:0.2rem;">🚨 ${{ue.explicit_failures[0].procedure}} (${{ue.explicit_failures[0].cause}})</div>`;
                }}

                tr.innerHTML = `
                    <td><span class="pill ${{pillCls}}">${{pillTxt}}</span></td>
                    <td><strong style="font-family:var(--font-code); color:#fff; font-size:0.95rem;">${{ue.context_id}}</strong></td>
                    <td>
                        <div style="display:flex; flex-direction:column; gap:0.25rem;">
                            <span class="badge badge-ran">${{ranStr}}</span>
                            <span class="badge badge-amf">${{amfStr}}</span>
                        </div>
                    </td>
                    <td style="font-family:var(--font-code); font-size:0.8rem; color:var(--text-muted);">
                        gNB: ${{ue.gnb_ip || '192.168.10.23'}}<br>AMF: ${{ue.amf_ip || '192.168.10.132'}}
                    </td>
                    <td>
                        <div>${{procsHtml}}</div>
                        ${{diagSummary}}
                    </td>
                    <td>
                        <button style="background:rgba(99,102,241,0.2); color:#a5b4fc; border:1px solid rgba(99,102,241,0.4); padding:0.35rem 0.75rem; border-radius:6px; font-size:0.78rem; cursor:pointer;">Inspect Flow ➔</button>
                    </td>
                `;
                tr.onclick = () => openModal(ue);
                tbody.appendChild(tr);
            }});

            document.getElementById('cnt-failed').textContent = failed;
            document.getElementById('cnt-inc').textContent = inc;
        }}

        function formatTimestamp(ts) {{
            if (!ts) return '';
            const str = String(ts).trim();
            if (str.includes('T')) {{
                const timePart = str.split('T')[1] || str;
                return timePart.replace(/(\\.\\d{{3}})\\d*(Z?)/, '$1$2');
            }}
            if (str.endsWith('s')) {{
                const num = parseFloat(str.slice(0, -1));
                return !isNaN(num) ? `${{num.toFixed(3)}}s` : str;
            }}
            const num = parseFloat(str);
            return !isNaN(num) ? `${{num.toFixed(3)}}s` : str;
        }}

        function openModal(ue) {{
            document.getElementById('modal-title').textContent = `${{ue.context_id}} Signalling Sequence Flow`;
            const body = document.getElementById('modal-body');
            body.innerHTML = '';

            (ue.timeline || []).forEach(evt => {{
                const row = document.createElement('div');
                row.className = 'seq-row';
                const isGnb = (evt.direction || '').includes('gNB -> AMF');
                row.innerHTML = `
                    <div class="seq-frame">
                        <span class="frame-num">Frame #${{evt.frame_number}}</span>
                        <span class="frame-ts">${{formatTimestamp(evt.timestamp)}}</span>
                    </div>
                    <div class="seq-msg">
                        <div>
                            <strong>${{evt.message_type}}</strong>
                            ${{evt.cause_code ? `<div style="color:${{evt.procedure_status === 'Failed' ? '#fca5a5' : 'var(--text-muted)'}}; font-size:0.75rem; margin-top:0.2rem;">Cause: ${{evt.cause_code}}</div>` : ''}}
                        </div>
                        <span style="font-weight:600; color:${{isGnb ? '#a5b4fc' : '#67e8f9'}};">${{evt.direction}}</span>
                    </div>
                `;
                body.appendChild(row);
            }});

            document.getElementById('modal').classList.remove('hidden');
        }}

        function closeModal() {{
            document.getElementById('modal').classList.add('hidden');
        }}
    </script>
</body>
</html>"""
