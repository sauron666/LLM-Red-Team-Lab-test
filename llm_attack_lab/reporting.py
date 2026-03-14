from pathlib import Path
from typing import Dict, List
from jinja2 import Template
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from .utils.json_utils import pretty_json
import datetime

HTML_TEMPLATE = Template("""<!doctype html><html><head><meta charset='utf-8'><title>LLM Attack Lab Report</title>
<style>body{font-family:Arial;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;font-size:12px}th{background:#f3f3f3}pre{background:#f7f7f7;padding:8px;overflow:auto}</style>
</head><body><h1>LLM Attack Lab Report</h1><small>{{generated}}</small>
<h2>Summary</h2><pre>{{summary}}</pre>
<h2>Findings</h2><table><tr><th>ID</th><th>Category</th><th>Status</th><th>Severity</th><th>Confidence</th><th>Evidence</th></tr>
{% for f in findings %}<tr><td>{{f.get('attack_id')}}</td><td>{{f.get('category')}}</td><td>{{f.get('status')}}</td><td>{{f.get('severity')}}</td><td>{{f.get('confidence')}}</td><td><pre>{{(f.get('evidence','') or '')[:600]}}</pre></td></tr>{% endfor %}
</table></body></html>""")
def export_html(path: Path, summary: Dict, findings: List[Dict]):
    html = HTML_TEMPLATE.render(generated=str(datetime.datetime.now()), summary=pretty_json(summary), findings=findings)
    Path(path).write_text(html, encoding="utf-8")
def export_pdf(path: Path, summary: Dict, findings: List[Dict]):
    c=canvas.Canvas(str(path), pagesize=letter)
    w,h=letter
    y=h-40
    c.setFont("Helvetica-Bold",16); c.drawString(40,y,"LLM Attack Lab Report"); y-=22
    c.setFont("Helvetica",10); c.drawString(40,y,"Summary:"); y-=14
    for line in pretty_json(summary).splitlines():
        if y<60: c.showPage(); y=h-40
        c.drawString(40,y,line[:120]); y-=12
    y-=10; c.setFont("Helvetica-Bold",12); c.drawString(40,y,"Findings:"); y-=18
    c.setFont("Helvetica",9)
    for f in findings:
        if y<80: c.showPage(); y=h-40
        c.drawString(40,y,f"{f.get('attack_id')} | {f.get('category')} | {f.get('status')} | {f.get('severity')}"); y-=12
        ev=(f.get("evidence","") or "").replace("\n"," ")
        c.drawString(52,y,ev[:140]); y-=14
    c.save()
