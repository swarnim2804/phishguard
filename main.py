import os
import re
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# For persistent cloud storage, set DATABASE_URL to a managed PostgreSQL URL.
# Local development defaults to SQLite. Free-host filesystems may be ephemeral.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishing_scans.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    verdict = Column(String(30), nullable=False)
    risk_score = Column(Float, nullable=False)
    reasons = Column(String(2000), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Phishing URL Detection Demo",
    description="Educational URL risk screening demo. It is not a production security product.",
    version="1.0.0",
)

class URLRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

SUSPICIOUS_WORDS = {
    "login", "verify", "account", "update", "secure", "password",
    "wallet", "banking", "signin", "confirm", "payment", "recover"
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".click", ".country", ".gq", ".tk", ".work"}

def analyze_url(raw_url: str):
    value = raw_url.strip()
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "http://" + value
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if not host or " " in host:
        raise ValueError("Enter a valid hostname or URL, such as https://example.com")

    score = 0.0
    reasons = []

    if parsed.scheme.lower() != "https":
        score += 12
        reasons.append("Uses HTTP rather than HTTPS")
    if len(value) > 75:
        score += 12
        reasons.append("Unusually long URL")
    if "@" in parsed.netloc:
        score += 25
        reasons.append("Contains an @ symbol in the network location")
    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("Uses an IP address instead of a domain name")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        score += 18
        reasons.append("Contains an internationalized/punycode domain")
    labels = host.split(".")
    if len(labels) >= 5:
        score += 12
        reasons.append("Contains many subdomains")
    if any(word in value.lower() for word in SUSPICIOUS_WORDS):
        score += 12
        reasons.append("Contains words commonly used in account-lure URLs")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("Uses a TLD that deserves additional scrutiny")
    if "-" in host:
        score += 5
        reasons.append("Domain contains hyphens")

    score = min(score, 100.0)
    if score >= 45:
        verdict = "High risk"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Lower risk"

    if not reasons:
        reasons.append("No configured heuristic indicators were detected")
    return {"url": value, "verdict": verdict, "risk_score": round(score, 1), "reasons": reasons}

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.get("/health")
def health():
    return {"status": "ok", "service": "phishing-url-detection-demo"}

@app.post("/api/scan")
def scan(request: URLRequest):
    try:
        result = analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    db = SessionLocal()
    try:
        row = Scan(
            url=result["url"],
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            reasons="; ".join(result["reasons"]),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        result["scan_id"] = row.id
        result["created_at"] = row.created_at.isoformat()
    finally:
        db.close()
    return result

@app.get("/api/history")
def history(limit: int = 10):
    limit = max(1, min(limit, 50))
    db = SessionLocal()
    try:
        rows = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
        return [{
            "id": row.id, "url": row.url, "verdict": row.verdict,
            "risk_score": row.risk_score, "created_at": row.created_at.isoformat()
        } for row in rows]
    finally:
        db.close()

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard | URL Risk Check</title>
<style>
:root{--bg:#0b1020;--panel:#121a2e;--panel2:#18223a;--ink:#edf3ff;--muted:#a8b4ce;--line:#293651;--cyan:#65e5d1;--blue:#83a7ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0%,#1c3156 0,transparent 35%),var(--bg);color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif;min-height:100vh}
main{max-width:1020px;margin:auto;padding:30px 20px 60px}.nav{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:14px}.logo{width:38px;height:38px;display:grid;place-items:center;background:#183c4a;border:1px solid #2b6b73;border-radius:12px;color:var(--cyan);font-weight:800}
.hero{padding:58px 0 30px;max-width:760px}.eyebrow{color:var(--cyan);font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:12px}h1{font-size:clamp(34px,6vw,58px);line-height:1.04;letter-spacing:-.04em;margin:14px 0}h1 span{color:var(--cyan)}p{color:var(--muted);line-height:1.65}.panel{background:linear-gradient(150deg,#15213a,#101729);border:1px solid var(--line);border-radius:20px;padding:22px;box-shadow:0 18px 55px #0003}.search{display:flex;gap:10px;margin-top:18px}.search input{flex:1;min-width:0;background:#0b1325;border:1px solid #354563;border-radius:12px;padding:16px;color:var(--ink);font-size:15px;outline:none}.search input:focus{border-color:var(--cyan)}button{border:0;border-radius:12px;padding:0 22px;background:var(--cyan);color:#072321;font-weight:800;font-size:14px;cursor:pointer}button:disabled{opacity:.55;cursor:wait}.examples{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.chip{background:#1b2942;color:#b8c7e1;border:1px solid #334461;border-radius:99px;padding:7px 10px;font-size:12px;cursor:pointer}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:18px}.result{display:none;margin-top:18px}.result-top{display:flex;justify-content:space-between;align-items:center;gap:12px}.pill{border-radius:99px;padding:7px 11px;font-weight:800;font-size:12px}.score{font-size:34px;font-weight:800}.meter{height:8px;border-radius:20px;background:#26344d;overflow:hidden;margin:10px 0 16px}.meter span{display:block;height:100%;width:0%;background:var(--cyan);transition:width .3s}.reasons{padding-left:20px;color:var(--muted);line-height:1.8}.small{font-size:12px}.history-row{padding:12px 0;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:12px;font-size:13px}.history-row:last-child{border:0}.url{overflow-wrap:anywhere;color:#dce7ff}.tag{color:var(--cyan);font-size:12px}.foot{margin-top:24px;border-top:1px solid var(--line);padding-top:18px;font-size:12px;color:#8796b4}.status{min-height:22px;color:#ffcf88;font-size:13px;margin-top:10px}
@media(max-width:700px){.search{flex-direction:column}.search button{padding:15px}.grid{grid-template-columns:1fr}.hero{padding-top:38px}}
</style></head>
<body><main>
<div class="nav"><div class="logo">PG</div><div><strong>PhishGuard</strong><div class="small">Cloud URL risk screening demo</div></div><div style="margin-left:auto" class="tag">FT-III · CLOUD COMPUTING</div></div>
<section class="hero"><div class="eyebrow">Stay one step ahead</div><h1>Check a link before<br><span>you trust it.</span></h1><p>Screen a URL for common phishing indicators. This educational prototype uses transparent URL heuristics; it is not a trained ML model and cannot guarantee a site is safe.</p></section>
<section class="panel"><strong>URL risk checker</strong><p class="small">Enter a URL you want to inspect. Do not enter passwords or other personal information.</p>
<div class="search"><input id="url" type="text" placeholder="https://example.com" autocomplete="url"><button id="scan" onclick="scanUrl()">Analyze URL ↗</button></div>
<div class="examples"><button class="chip" onclick="example('https://example.com')">Example: ordinary URL</button><button class="chip" onclick="example('http://secure-login-account.example.top/verify')">Example: suspicious indicators</button></div><div id="status" class="status" role="status"></div></section>
<section id="result" class="panel result"><div class="result-top"><div><div class="small" style="color:var(--muted)">SCREENING RESULT</div><h2 id="verdict" style="margin:6px 0 0">—</h2></div><div style="text-align:right"><div class="small" style="color:var(--muted)">Heuristic risk score</div><div class="score"><span id="score">0</span><span class="small"> / 100</span></div></div></div><div class="meter"><span id="meter"></span></div><div class="small" style="color:var(--muted)">URL checked</div><div class="url" id="checked"></div><h3 style="font-size:15px;margin-bottom:6px">Indicators</h3><ul id="reasons" class="reasons"></ul><div id="scanid" class="small" style="color:var(--muted)"></div></section>
<div class="grid"><section class="panel"><div class="tag">HOW IT WORKS</div><h3>Lightweight URL analysis</h3><p class="small">The backend checks URL length, HTTP vs HTTPS, IP-address hosts, @ symbols, subdomain count, suspicious terms and selected TLDs. Each indicator adds to a rule-based score.</p><p class="small">A low score does not prove a URL is legitimate. Attackers can use HTTPS and compromised trusted websites.</p></section><section class="panel"><div class="tag">RECENT SCANS</div><h3>History</h3><div id="history" class="small" style="color:var(--muted)">No scans yet.</div></section></div>
<div class="foot">Academic demo only · No live site reputation lookup · Avoid submitting sensitive URLs · Predictions are indicative, not a security guarantee.</div>
</main>
<script>
function example(v){document.getElementById('url').value=v;document.getElementById('url').focus()}
async function scanUrl(){const input=document.getElementById('url'),btn=document.getElementById('scan'),status=document.getElementById('status');const url=input.value.trim();if(!url){status.textContent='Please enter a URL first.';return}btn.disabled=true;status.textContent='Analyzing URL…';try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Could not analyze this URL');document.getElementById('result').style.display='block';document.getElementById('verdict').textContent=d.verdict;document.getElementById('score').textContent=d.risk_score;document.getElementById('meter').style.width=d.risk_score+'%';document.getElementById('checked').textContent=d.url;document.getElementById('reasons').innerHTML=d.reasons.map(x=>'<li>'+escapeHtml(x)+'</li>').join('');document.getElementById('scanid').textContent='Scan ID: '+d.scan_id+' · '+new Date(d.created_at).toLocaleString();status.textContent='Analysis complete.';await loadHistory()}catch(e){status.textContent=e.message}finally{btn.disabled=false}}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function loadHistory(){try{const r=await fetch('/api/history?limit=5'),items=await r.json();const el=document.getElementById('history');if(!items.length){el.textContent='No scans yet.';return}el.innerHTML=items.map(x=>'<div class="history-row"><div style="min-width:0"><div class="url">'+escapeHtml(x.url)+'</div><div class="small">'+new Date(x.created_at).toLocaleString()+'</div></div><div style="text-align:right;white-space:nowrap"><strong>'+escapeHtml(x.verdict)+'</strong><div class="small">Score '+x.risk_score+'</div></div></div>').join('')}catch(e){}}
document.getElementById('url').addEventListener('keydown',e=>{if(e.key==='Enter')scanUrl()});loadHistory();
</script></body></html>"""
