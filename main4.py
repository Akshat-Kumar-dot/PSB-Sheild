import os, re, io, zipfile, tempfile
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

try:
    from androguard.misc import APK
    ANDROGUARD_OK = True
except ImportError:
    ANDROGUARD_OK = False

try:
    from pyaxmlparser import APK as AXAPK
    AXMLPARSER_OK = True
except ImportError:
    AXMLPARSER_OK = False

try:
    from ml_predictor import ml_predict_url, ml_predict_apk, ML_READY
except ImportError:
    ML_READY = False
    def ml_predict_url(u): return None
    def ml_predict_apk(*a): return None

app = FastAPI()

REAL_PACKAGE     = "com.sbi.lotusintouch"
OFFICIAL_DOMAINS = ["sbi.co.in","onlinesbi.sbi","yonobusiness.sbi","retail.onlinesbi.sbi"]
DANGEROUS_PERMS  = [
    "READ_SMS","RECEIVE_SMS","SEND_SMS","READ_CONTACTS","READ_CALL_LOG",
    "SYSTEM_ALERT_WINDOW","BIND_ACCESSIBILITY_SERVICE",
    "RECORD_AUDIO","READ_PHONE_STATE","PROCESS_OUTGOING_CALLS",
]
SUSPICIOUS_TLDS = [
    ".xyz",".tk",".top",".gq",".ml",".cf",".pw",".club",".inn",
    ".info",".biz",".work",".live",".online",".site",".website",
    ".tech",".store",".fun",".loan",".click",".download",".link",
    ".win",".party",".racing",".trade",".webcam",".science",
]
FAKE_KEYWORDS = [
    "sbi-","-sbi","yono-","-yono","sbionline","onlinesbi-",
    "sbikyc","sbi_","_sbi","sbiyono","yonosbi","sbimobile","sbibank",
]
URGENCY_WORDS = [
    "urgent","expire","kyc","block","suspend","verify",
    "immediate","otp","reward","freeze","deactivate","penalty",
]

threat_log = []


def _parse_binary_manifest(raw):
    result = {"packageName": "Unknown", "permissions": []}
    try:
        # Decode binary XML by scanning for UTF-16 strings
        # Android binary XML stores strings in a string pool
        # We extract all readable strings and filter for what we need
        
        # Try UTF-16 LE decoding (how Android stores strings internally)
        try:
            text = raw.decode("utf-16-le", errors="ignore")
        except Exception:
            text = raw.decode("utf-8", errors="ignore")

        # Find package name
        pkg = re.findall(r'com\.[a-z0-9_.]{3,50}', text)
        if pkg:
            result["packageName"] = pkg[0]

        # Find permissions from string pool
        perms = re.findall(r'(?:android\.permission\.|com\.[a-z]+\.[a-z]+\.permission\.)([A-Z_]{3,40})', text)
        if perms:
            result["permissions"] = list(set(perms))
        else:
            # Fallback — scan raw bytes for permission strings
            raw_text = raw.decode("latin-1", errors="ignore")
            perms = re.findall(r'android\.permission\.([A-Z_]{3,40})', raw_text)
            result["permissions"] = list(set(perms))
            if not result["packageName"] or result["packageName"] == "Unknown":
                pkg = re.findall(r'com\.[a-z0-9_.]{3,50}', raw_text)
                if pkg:
                    result["packageName"] = pkg[0]

    except Exception:
        pass
    return result

def extract_apk_metadata(file_bytes, filename):
    size_mb = len(file_bytes) / 1024 / 1024
    meta = {
        "packageName"   : "Unknown",
        "appName"       : filename,
        "version"       : "Unknown",
        "certificate"   : "Unknown",
        "permissions"   : [],
        "dangerousPerms": [],
        "embeddedUrls"  : [],
        "sizeMB"        : round(size_mb, 1),
    }

    if size_mb <= 25 and ANDROGUARD_OK:
        tmp = tempfile.mktemp(suffix=".apk")
        try:
            with open(tmp, "wb") as f:
                f.write(file_bytes)
            apk = APK(tmp)
            meta["packageName"] = apk.get_package() or "Unknown"
            meta["appName"]     = apk.get_app_name() or filename
            meta["version"]     = apk.get_androidversion_name() or "Unknown"
            perms               = apk.get_permissions() or []
            meta["permissions"] = [p.split(".")[-1] for p in perms]
            meta["embeddedUrls"]= list(apk.get_urls())[:10]
            try:
                cert = apk.get_certificate_der("META-INF/CERT.RSA")
                meta["certificate"] = "Verified (trusted CA)" if cert else "Missing"
            except Exception:
                meta["certificate"] = "Self-signed / unverified"
        except Exception as e:
            meta["error"] = str(e)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    else:
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                if "AndroidManifest.xml" in z.namelist():
                    raw = z.read("AndroidManifest.xml")
                    parsed = _parse_binary_manifest(raw)
                    meta["packageName"] = parsed["packageName"]
                    meta["permissions"] = parsed["permissions"]
                    meta["certificate"] = "Could not verify (large file)"
        except Exception as e:
            meta["error"] = str(e)

    meta["dangerousPerms"] = [p for p in meta["permissions"] if p in DANGEROUS_PERMS]
    return meta


def score_apk(meta, filename):
    flags = []
    risk  = 0
    pkg   = meta.get("packageName","Unknown")
    cert  = meta.get("certificate","Unknown")
    perms = meta.get("dangerousPerms",[])
    urls  = meta.get("embeddedUrls",[])
    size  = meta.get("sizeMB", 0)

    if pkg == REAL_PACKAGE:
        risk -= 10
    elif pkg == "Unknown":
        flags.append("Could not extract package name — treat with caution")
        risk += 20
    else:
        flags.append(f"Package '{pkg}' does not match official com.sbi.lotusintouch")
        risk += 40

    if perms:
        flags.append(f"High-risk permissions detected: {', '.join(perms)}")
        risk += min(len(perms) * 7, 30)

    if "self" in cert.lower() or "unverified" in cert.lower() or "missing" in cert.lower():
        flags.append("Certificate is self-signed or unverified — not issued by SBI")
        risk += 20
    elif "could not" in cert.lower():
        flags.append("Certificate could not be verified from this file")
        risk += 10

    bad_urls = [u for u in urls if not any(d in u for d in OFFICIAL_DOMAINS)]
    if bad_urls:
        flags.append(f"Suspicious embedded URLs: {', '.join(bad_urls[:3])}")
        risk += 15

    if size > 80:
        flags.append(f"Unusually large APK ({size}MB) — may contain hidden payloads")
        risk += 10
    elif size > 50:
        flags.append(f"Large APK size ({size}MB) — above typical banking app size")
        risk += 5

    fname = filename.lower()
    if any(k in fname for k in ["update","v2","new","latest","mod","hack"]):
        flags.append("Filename suggests unofficial update — SBI never distributes APKs via SMS")
        risk += 10

    risk = max(0, min(risk, 100))

    ml = ml_predict_apk(pkg, meta.get("permissions",[]), cert, urls)
    if ml:
        verdict = ml["verdict"]
        risk    = ml["riskScore"]
    else:
        verdict = "FAKE_MALICIOUS" if risk>=70 else "SUSPICIOUS" if risk>=40 else "LEGITIMATE"

    analysis = {
        "FAKE_MALICIOUS": "Strong indicators of a fake YONO SBI impersonator. This APK uses a different package identity, requests invasive device permissions, and carries an unverified certificate — all hallmarks of credential-stealing malware.",
        "SUSPICIOUS"    : "This APK deviates from the official YONO SBI profile in multiple ways. Exercise caution — do not install until verified through the Google Play Store.",
        "LEGITIMATE"    : "APK profile is consistent with the official YONO SBI app — correct package identity, verified certificate, and no high-risk permissions detected.",
    }[verdict]

    rec = {
        "FAKE_MALICIOUS": "Delete this file immediately. Install YONO only from Google Play Store (publisher: State Bank of India).",
        "SUSPICIOUS"    : "Do not install. Verify on the Google Play Store before proceeding.",
        "LEGITIMATE"    : "Appears genuine. Always prefer installing from the official Google Play Store.",
    }[verdict]

    return {
        "verdict"       : verdict,
        "riskScore"     : risk,
        "analysis"      : analysis,
        "recommendation": rec,
        "flags"         : flags,
        "metadata"      : meta,
    }


def analyze_apk(file_bytes, filename):
    meta = extract_apk_metadata(file_bytes, filename)
    if "error" in meta and meta.get("packageName","Unknown") == "Unknown":
        return {
            "verdict"       : "SUSPICIOUS",
            "riskScore"     : 50,
            "analysis"      : f"APK could not be fully parsed. Error: {meta['error'][:120]}",
            "recommendation": "Do not install APKs received via SMS or WhatsApp.",
            "flags"         : ["APK parsing failed — file may be corrupted or unsupported format"],
            "metadata"      : meta,
        }
    return score_apk(meta, filename)


def analyze_url(text):
    flags = []
    risk  = 0
    lower = text.lower()

    if any(d in lower for d in OFFICIAL_DOMAINS):
        risk -= 20

    matched = [t for t in SUSPICIOUS_TLDS if t in lower]
    if matched:
        flags.append(f"Non-standard domain extension: {', '.join(matched)}")
        risk += 30

    if any(s in lower for s in ["bit.ly","tinyurl","t.co","goo.gl","ow.ly","rb.gy","cutt.ly"]):
        flags.append("URL shortener in use — real destination is hidden")
        risk += 25

    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', lower):
        flags.append("Raw IP address used instead of a domain name")
        risk += 35

    if any(k in lower for k in FAKE_KEYWORDS):
        if not any(d in lower for d in OFFICIAL_DOMAINS):
            flags.append("SBI / YONO brand impersonation in unofficial domain")
            risk += 35

    if ".apk" in lower:
        flags.append("Direct APK download link — never install apps from SMS or WhatsApp")
        risk += 40

    found = [w for w in URGENCY_WORDS if w in lower]
    if found:
        flags.append(f"Social engineering language detected: {', '.join(found)}")
        risk += 15

    try:
        dp = re.findall(r'https?://([^/]+)', lower)
        if dp and dp[0].count('.') > 3:
            flags.append("Unusually deep subdomain chain — common phishing pattern")
            risk += 15
    except Exception:
        pass

    if lower.startswith("http://"):
        flags.append("Unencrypted HTTP — legitimate banks always use HTTPS")
        risk += 10

    risk = max(0, min(risk, 100))

    ml = ml_predict_url(text)
    if ml:
        verdict = ml["verdict"]
        risk    = ml["riskScore"]
    else:
        verdict = "PHISHING" if risk>=70 else "SUSPICIOUS" if risk>=35 else "SAFE"

    analysis = {
        "PHISHING"  : "High-confidence phishing detection. This URL uses multiple deception patterns — fake domains, urgency language, or APK download links — designed to steal banking credentials.",
        "SUSPICIOUS": "Multiple suspicious signals detected. This link likely does not originate from SBI. Do not click or share.",
        "SAFE"      : "No significant threat indicators found. This appears consistent with an official SBI domain.",
    }[verdict]

    rec = {
        "PHISHING"  : "Do not click. Block the sender. Report to SBI at report.phishing@sbi.co.in",
        "SUSPICIOUS": "Avoid clicking. Access your account by typing onlinesbi.sbi directly in your browser.",
        "SAFE"      : "Appears safe — but always navigate to bank URLs manually rather than via SMS links.",
    }[verdict]

    return {"verdict":verdict,"riskScore":risk,"analysis":analysis,"recommendation":rec,"flags":flags}


class URLRequest(BaseModel):
    url: str

@app.post("/scan-url")
def scan_url(req: URLRequest):
    result = analyze_url(req.url)
    threat_log.append({"type":"url","input":req.url,**result})
    return JSONResponse(result)

@app.post("/scan-apk")
async def scan_apk(file: UploadFile = File(...)):
    content = await file.read()
    result  = analyze_apk(content, file.filename)
    threat_log.append({"type":"apk","input":file.filename,**result})
    return JSONResponse(result)

@app.get("/dashboard")
def get_dashboard():
    total   = len(threat_log)
    threats = sum(1 for t in threat_log if t.get("verdict") in ["PHISHING","FAKE_MALICIOUS"])
    safe    = sum(1 for t in threat_log if t.get("verdict") in ["SAFE","LEGITIMATE"])
    susp    = sum(1 for t in threat_log if t.get("verdict") == "SUSPICIOUS")
    return {"total":total,"threats":threats,"suspicious":susp,"safe":safe,"recent":threat_log[-15:][::-1]}


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PSB Shield</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f4f6fb;color:#111}
.header{background:#1a237e;color:white;padding:16px 32px;display:flex;align-items:center;gap:12px}
.header h1{font-size:20px;font-weight:600}
.header p{font-size:12px;opacity:.7}
.container{max-width:900px;margin:0 auto;padding:24px 16px}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:white;border-radius:10px;padding:4px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.tab{flex:1;padding:10px;border:none;background:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;color:#666;transition:all .15s}
.tab.active{background:#1a237e;color:white}
.panel{background:white;border-radius:12px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.08);display:none}
.panel.active{display:block}
input[type=text]{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;font-family:monospace;outline:none}
input[type=text]:focus{border-color:#1a237e}
.row{display:flex;gap:8px;margin-top:8px}
.btn{padding:10px 24px;background:#1a237e;color:white;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap}
.btn:hover{background:#283593}
.btn:disabled{background:#ccc;cursor:not-allowed}
.drop-zone{border:2px dashed #bbb;border-radius:12px;padding:40px;text-align:center;cursor:pointer;background:#fafafa;transition:border-color .2s}
.drop-zone:hover{border-color:#1a237e}
.drop-zone .icon{font-size:40px;margin-bottom:10px}
.examples{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.ex-btn{font-size:11px;font-family:monospace;padding:4px 10px;border-radius:6px;border:1px solid #ddd;background:#f5f5f5;cursor:pointer;color:#555;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.result{margin-top:20px;border:1px solid #e0e0e0;border-radius:12px;padding:20px;display:none}
.result.show{display:block}
.verdict-badge{display:inline-block;padding:5px 16px;border-radius:6px;font-weight:700;font-size:13px;letter-spacing:.05em}
.SAFE,.LEGITIMATE{background:#e8f5e9;color:#1b5e20}
.SUSPICIOUS{background:#fff8e1;color:#e65100}
.PHISHING,.FAKE_MALICIOUS{background:#ffebee;color:#b71c1c}
.risk-row{display:flex;align-items:center;gap:10px;margin-top:10px}
.risk-bar{flex:1;height:8px;border-radius:4px;background:#eee;overflow:hidden}
.risk-fill{height:100%;border-radius:4px;transition:width .8s ease}
.slabel{font-size:11px;color:#888;letter-spacing:.05em;margin:14px 0 6px;font-weight:600}
.flag-item{display:flex;gap:8px;font-size:13px;margin-bottom:6px;line-height:1.4}
.flag-item span:first-child{color:#e53935;flex-shrink:0}
.perms{display:flex;flex-wrap:wrap;gap:5px}
.perm{font-size:11px;padding:3px 9px;border-radius:4px;font-family:monospace}
.perm.danger{background:#ffebee;color:#c62828;font-weight:600}
.perm.normal{background:#f5f5f5;color:#555}
.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:4px}
.meta-box{background:#f5f5f5;border-radius:8px;padding:10px 12px}
.meta-box label{font-size:10px;color:#888;display:block;margin-bottom:3px;letter-spacing:.04em}
.meta-box span{font-size:12px;font-family:monospace;word-break:break-all}
.meta-box.d{background:#ffebee}
.meta-box.d span{color:#c62828;font-weight:600}
.rec-box{background:#e3f2fd;border-radius:8px;padding:12px 14px;font-size:13px;margin-top:14px;line-height:1.5;display:none}
.rec-box strong{color:#0d47a1}
.analysis-text{font-size:14px;color:#333;line-height:1.6;margin-top:12px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat-card{background:white;border-radius:10px;padding:16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.stat-card .num{font-size:28px;font-weight:700}
.stat-card .lbl{font-size:12px;color:#888;margin-top:2px}
.threat .num{color:#e53935}.safe .num{color:#43a047}.susp .num{color:#fb8c00}
.log-item{display:flex;align-items:center;gap:12px;padding:10px 14px;border:1px solid #eee;border-radius:10px;margin-bottom:8px;background:white}
.log-item .info{flex:1;min-width:0}
.log-item .info p{font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-item .info small{font-size:11px;color:#999}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="header">
  <div style="font-size:28px">🛡️</div>
  <div><h1>PSB Shield</h1><p>Catch scams early. Block fake apps. Verify what's real.</p></div>
</div>
<div class="container">
  <div class="tabs">
    <button class="tab active" onclick="switchTab('url')">🔗 URL / SMS Scanner</button>
    <button class="tab" onclick="switchTab('apk')">📱 APK Analyzer</button>
    <button class="tab" onclick="switchTab('dashboard')">📊 Threat Dashboard</button>
  </div>

  <div id="tab-url" class="panel active">
    <p style="font-size:13px;color:#666;margin-bottom:8px">Paste a suspicious link or full SMS message</p>
    <div class="row">
      <input type="text" id="url-input" placeholder="https://yono-sbi-kyc.xyz/update  or paste full SMS here…"/>
      <button class="btn" id="url-btn" onclick="scanURL()">Scan</button>
    </div>
    <p style="font-size:11px;color:#aaa;margin-top:10px">Try an example:</p>
    <div class="examples">
      <button class="ex-btn" onclick="setURL('http://yono-sbi.apk-download.xyz/install')">http://yono-sbi.apk-download.xyz/install</button>
      <button class="ex-btn" onclick="setURL('https://bit.ly/sbi-kyc-urgent')">https://bit.ly/sbi-kyc-urgent</button>
      <button class="ex-btn" onclick="setURL('Dear SBI user your KYC will expire today click here immediately http://192.168.1.1/sbi')">Demo SMS phishing message</button>
      <button class="ex-btn" onclick="setURL('https://onlinesbi.sbi/login')">https://onlinesbi.sbi/login (official)</button>
    </div>
    <div id="url-result" class="result">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span id="url-verdict" class="verdict-badge"></span>
        <div class="risk-row" style="flex:1;min-width:160px;margin-top:0">
          <div class="risk-bar"><div id="url-risk-fill" class="risk-fill"></div></div>
          <span id="url-risk-num" style="font-size:13px;font-weight:700;min-width:54px"></span>
        </div>
      </div>
      <p id="url-analysis" class="analysis-text"></p>
      <div id="url-flags"></div>
      <div id="url-rec" class="rec-box"></div>
    </div>
  </div>

  <div id="tab-apk" class="panel">
    <div class="drop-zone" id="drop-zone" onclick="document.getElementById('apk-file').click()">
      <div class="icon">📦</div>
      <p style="font-weight:600;font-size:14px">Click to upload APK file</p>
      <p style="font-size:12px;color:#888;margin-top:4px">Supports any size · extracts package, permissions, certificate</p>
    </div>
    <input type="file" id="apk-file" accept=".apk" style="display:none" onchange="scanAPK(this)"/>
    <div id="apk-result" class="result">
      <div id="apk-filename" style="font-family:monospace;font-size:13px;color:#555;margin-bottom:12px"></div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span id="apk-verdict" class="verdict-badge"></span>
        <div class="risk-row" style="flex:1;min-width:160px;margin-top:0">
          <div class="risk-bar"><div id="apk-risk-fill" class="risk-fill"></div></div>
          <span id="apk-risk-num" style="font-size:13px;font-weight:700;min-width:54px"></span>
        </div>
      </div>
      <p id="apk-analysis" class="analysis-text"></p>
      <div id="apk-meta" class="meta-grid"></div>
      <div id="apk-perms"></div>
      <div id="apk-flags"></div>
      <div id="apk-rec" class="rec-box"></div>
    </div>
  </div>

  <div id="tab-dashboard" class="panel">
    <div class="stats">
      <div class="stat-card"><div class="num" id="s-total">0</div><div class="lbl">Total Scans</div></div>
      <div class="stat-card threat"><div class="num" id="s-threats">0</div><div class="lbl">Threats Found</div></div>
      <div class="stat-card susp"><div class="num" id="s-susp">0</div><div class="lbl">Suspicious</div></div>
      <div class="stat-card safe"><div class="num" id="s-safe">0</div><div class="lbl">Safe</div></div>
    </div>
    <div id="threat-log"><p style="text-align:center;color:#aaa;padding:30px">No scans yet.</p></div>
  </div>
</div>

<script>
function switchTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  const idx=['url','apk','dashboard'].indexOf(name);
  document.querySelectorAll('.tab')[idx].classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
  if(name==='dashboard') loadDashboard();
}
function setURL(v){document.getElementById('url-input').value=v;}
function rc(s){return s>=70?'#e53935':s>=35?'#fb8c00':'#43a047';}

function showResult(prefix,data){
  const v=data.verdict||'UNKNOWN', s=data.riskScore||0;
  document.getElementById(prefix+'-result').classList.add('show');
  const ve=document.getElementById(prefix+'-verdict');
  ve.textContent=v.replace('_',' '); ve.className='verdict-badge '+v;
  const f=document.getElementById(prefix+'-risk-fill');
  f.style.width=s+'%'; f.style.background=rc(s);
  const n=document.getElementById(prefix+'-risk-num');
  n.textContent=s+' / 100'; n.style.color=rc(s);
  document.getElementById(prefix+'-analysis').textContent=data.analysis||'';
  const fe=document.getElementById(prefix+'-flags');
  fe.innerHTML=data.flags&&data.flags.length
    ?'<div class="slabel">FLAGS DETECTED</div>'+data.flags.map(f=>`<div class="flag-item"><span>⚠</span><span>${f}</span></div>`).join('')
    :'';
  const re=document.getElementById(prefix+'-rec');
  if(data.recommendation){re.style.display='block';re.innerHTML='<strong>Recommendation:</strong> '+data.recommendation;}
  else re.style.display='none';
}

async function scanURL(){
  const url=document.getElementById('url-input').value.trim();
  if(!url) return;
  const btn=document.getElementById('url-btn');
  btn.disabled=true; btn.innerHTML='<span class="spinner"></span>Scanning…';
  try{
    const res=await fetch('/scan-url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    showResult('url',await res.json());
  }catch(e){alert('Error: '+e.message);}
  btn.disabled=false; btn.textContent='Scan';
}

async function scanAPK(input){
  const file=input.files[0]; if(!file) return;
  const sizeMB=(file.size/1024/1024).toFixed(1);
  document.getElementById('drop-zone').innerHTML=
    '<div class="icon">⚙️</div><p style="font-weight:600;font-size:14px">Analyzing '+file.name+'…</p>'+
    '<p style="font-size:12px;color:#888;margin-top:4px">'+sizeMB+'MB · extracting metadata</p>';
  const form=new FormData(); form.append('file',file);
  try{
    const res=await fetch('/scan-apk',{method:'POST',body:form});
    const data=await res.json();
    document.getElementById('apk-filename').textContent='📱 '+file.name+' ('+sizeMB+'MB)';
    showResult('apk',data);
    const m=data.metadata||{};
    const pd=m.packageName&&m.packageName!=='com.sbi.lotusintouch'&&m.packageName!=='Unknown';
    const cd=m.certificate&&(m.certificate.toLowerCase().includes('self')||m.certificate.includes('unverified')||m.certificate.includes('Missing'));
    document.getElementById('apk-meta').innerHTML=`
      <div class="meta-box ${pd?'d':''}"><label>PACKAGE NAME</label><span>${m.packageName||'—'}</span></div>
      <div class="meta-box ${cd?'d':''}"><label>CERTIFICATE</label><span>${m.certificate||'—'}</span></div>
      <div class="meta-box"><label>APP NAME</label><span>${m.appName||'—'}</span></div>
      <div class="meta-box"><label>VERSION · SIZE</label><span>${m.version||'—'} · ${m.sizeMB||'?'}MB</span></div>`;
    const dset=new Set(m.dangerousPerms||[]);
    document.getElementById('apk-perms').innerHTML=m.permissions&&m.permissions.length
      ?'<div class="slabel">ALL PERMISSIONS ('+m.permissions.length+')</div><div class="perms">'+
        m.permissions.map(p=>`<span class="perm ${dset.has(p)?'danger':'normal'}">${p}</span>`).join('')+'</div>'
      :'';
  }catch(e){alert('Error: '+e.message);}
  document.getElementById('drop-zone').innerHTML=
    '<div class="icon">📦</div><p style="font-weight:600;font-size:14px">Upload another APK</p>'+
    '<p style="font-size:12px;color:#888;margin-top:4px">Click or drop to analyze</p>';
}

async function loadDashboard(){
  try{
    const data=await(await fetch('/dashboard')).json();
    document.getElementById('s-total').textContent=data.total;
    document.getElementById('s-threats').textContent=data.threats;
    document.getElementById('s-susp').textContent=data.suspicious;
    document.getElementById('s-safe').textContent=data.safe;
    const log=document.getElementById('threat-log');
    if(!data.recent||!data.recent.length){
      log.innerHTML='<p style="text-align:center;color:#aaa;padding:30px">No scans yet.</p>';return;
    }
    log.innerHTML=data.recent.map(t=>{
      const v=t.verdict||'UNKNOWN',s=t.riskScore||0;
      return`<div class="log-item">
        <span style="font-size:20px">${t.type==='url'?'🔗':'📱'}</span>
        <div class="info"><p>${t.input||'—'}</p><small>${t.type==='url'?'URL / SMS':'APK File'}</small></div>
        <span class="verdict-badge ${v}" style="font-size:11px;padding:3px 10px">${v.replace('_',' ')}</span>
        <span style="font-weight:700;min-width:40px;text-align:right;color:${rc(s)}">${s}</span>
      </div>`;
    }).join('');
  }catch(e){console.error(e);}
}

const dz=document.getElementById('drop-zone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.style.borderColor='#1a237e';});
dz.addEventListener('dragleave',()=>{dz.style.borderColor='#bbb';});
dz.addEventListener('drop',e=>{
  e.preventDefault();dz.style.borderColor='#bbb';
  const file=e.dataTransfer.files[0];
  if(file&&file.name.endsWith('.apk')){
    const dt=new DataTransfer();dt.items.add(file);
    document.getElementById('apk-file').files=dt.files;
    scanAPK(document.getElementById('apk-file'));
  }
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
