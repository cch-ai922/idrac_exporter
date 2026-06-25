"""
guardian-controller (stdlib-only build)
========================================
Identical behaviour to app.py but with ZERO third-party packages — only the
Python standard library (http.server, urllib, ssl, json, threading). No
pip install needed; runs on any python3. Config is JSON (stdlib) instead of YAML.

Single replica only: incident state is in-memory by design.
"""
import os
import ssl
import json
import time
import base64
import logging
import threading
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("guardian")

CONFIG_PATH = os.environ.get("GUARDIAN_CONFIG", "/etc/guardian/config.json")
TOKEN = os.environ.get("GUARDIAN_TOKEN", "")
PORT = int(os.environ.get("GUARDIAN_PORT", "8080"))

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    cfg.setdefault("defaults", {})
    cfg.setdefault("hosts", {})
    return cfg

CONFIG = load_config()

def host_policy(instance):
    hosts = CONFIG.get("hosts", {})
    if instance not in hosts:
        return None
    pol = dict(CONFIG.get("defaults", {}))
    pol.update(hosts[instance] or {})
    pol["instance"] = instance
    return pol

# ---------------------------------------------------------------------------
# Redfish power control via urllib (stdlib) — Dell iDRAC / Lenovo XCC / Supermicro
# ---------------------------------------------------------------------------
def _ctx(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def redfish_reset(pol, reset_type):
    host = pol["instance"]
    base = "https://" + host
    ctx = _ctx(bool(pol.get("verify_tls", False)))
    auth = base64.b64encode(f'{pol["username"]}:{pol["password"]}'.encode()).decode()
    headers = {"Authorization": "Basic " + auth,
               "Accept": "application/json", "Content-Type": "application/json"}

    def get(path):
        req = urllib.request.Request(base + path, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return json.loads(r.read().decode())

    sys_id = pol.get("system_id")
    if sys_id:
        sys_path = "/redfish/v1/Systems/" + str(sys_id)
    else:
        members = get("/redfish/v1/Systems").get("Members", [])
        if not members:
            raise RuntimeError("no Redfish systems found")
        sys_path = members[0]["@odata.id"]

    data = get(sys_path)
    reset = data.get("Actions", {}).get("#ComputerSystem.Reset", {})
    target = reset.get("target", sys_path + "/Actions/ComputerSystem.Reset")
    allowed = reset.get("ResetType@Redfish.AllowableValues")
    if allowed and reset_type not in allowed:
        for alt in ("GracefulShutdown", "ForceOff", "PushPowerButton"):
            if alt in allowed:
                log.warning("%s: %s not allowed, using %s", host, reset_type, alt)
                reset_type = alt
                break
    body = json.dumps({"ResetType": reset_type}).encode()
    req = urllib.request.Request(base + target, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return f"Redfish {reset_type} -> {host} ({r.status})"

def do_power(instance, reset_type):
    pol = host_policy(instance)
    if not pol:
        raise KeyError("unknown host " + instance)
    if pol.get("dry_run"):
        msg = f"[DRY-RUN] would send {reset_type} to {instance}"
        log.warning(msg)
        return msg
    msg = redfish_reset(pol, reset_type)
    log.warning("POWER ACTION: %s", msg)
    return msg

# ---------------------------------------------------------------------------
# Incident state machine
# ---------------------------------------------------------------------------
incidents = {}
lock = threading.Lock()

def arm(instance, alertname, summary):
    pol = host_policy(instance)
    if not pol:
        log.warning("alert for unconfigured host %s — ignoring", instance)
        return
    with lock:
        inc = incidents.get(instance)
        if inc and inc["state"] in ("ARMED", "SHUTTING_DOWN", "DONE"):
            inc["alertname"], inc["summary"] = alertname, summary
            return
        grace = int(pol.get("grace_seconds", 120))
        incidents[instance] = {
            "instance": instance, "alertname": alertname, "summary": summary,
            "state": "ARMED", "armed_at": time.time(),
            "shutdown_at": time.time() + grace, "grace_seconds": grace,
            "auto_shutdown": bool(pol.get("auto_shutdown", True)),
            "dry_run": bool(pol.get("dry_run", False)),
            "reset_type": pol.get("reset_type", "GracefulShutdown"), "message": "",
        }
    log.warning("ARMED %s (%s): shutdown in %ss", instance, alertname, grace)

def resolve(instance):
    with lock:
        inc = incidents.get(instance)
        if inc and inc["state"] == "ARMED":
            inc["state"], inc["message"] = "RESOLVED", "alert cleared before timeout"
            log.info("RESOLVED %s", instance)

def shutdown_loop():
    while True:
        now = time.time()
        due = []
        with lock:
            for inc in incidents.values():
                if inc["state"] == "ARMED" and now >= inc["shutdown_at"]:
                    if not inc["auto_shutdown"]:
                        inc["state"] = "RESOLVED"
                        inc["message"] = "auto_shutdown disabled — warn only"
                    else:
                        inc["state"] = "SHUTTING_DOWN"
                        due.append(inc)
        for inc in due:
            try:
                msg = do_power(inc["instance"], inc["reset_type"])
                with lock:
                    inc["state"], inc["message"] = "DONE", msg
            except Exception as e:  # noqa: BLE001
                with lock:
                    inc["state"], inc["message"] = "FAILED", f"shutdown failed: {e}"
                log.error("shutdown FAILED for %s: %s", inc["instance"], e)
        time.sleep(1)

# ---------------------------------------------------------------------------
# HTTP handler (stdlib)
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quieter
        pass

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        if not TOKEN:
            return True
        return self.headers.get("Authorization") == "Bearer " + TOKEN

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            return self._send(200, HTML.encode(), "text/html; charset=utf-8")
        if path == "/healthz":
            return self._send(200, {"ok": True, "hosts": list(CONFIG["hosts"].keys())})
        if path == "/api/hosts":
            return self._send(200, {"hosts": list(CONFIG["hosts"].keys())})
        if path == "/api/incidents":
            now = time.time()
            out = []
            with lock:
                for inc in incidents.values():
                    d = dict(inc)
                    d["remaining"] = max(0, int(inc["shutdown_at"] - now)) if inc["state"] == "ARMED" else 0
                    out.append(d)
            return self._send(200, {"incidents": out, "now": now})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)
        force = q.get("force", ["false"])[0].lower() == "true"
        parts = [p for p in path.split("/") if p]

        if path == "/webhook":
            if not self._auth_ok():
                return self._send(401, {"error": "unauthorized"})
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            for a in payload.get("alerts", []):
                labels = a.get("labels", {})
                instance = labels.get("instance", "")
                if not instance:
                    continue
                if a.get("status") == "resolved":
                    resolve(instance)
                elif labels.get("guardian_action") == "shutdown":
                    summary = a.get("annotations", {}).get("summary", labels.get("alertname", ""))
                    arm(instance, labels.get("alertname", "alert"), summary)
            return self._send(200, {"received": len(payload.get("alerts", []))})

        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})

        # /api/incidents/{instance}/cancel | shutdown_now
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "incidents":
            instance, action = parts[2], parts[3]
            with lock:
                inc = incidents.get(instance)
            if not inc:
                return self._send(404, {"error": "no such incident"})
            if action == "cancel":
                with lock:
                    if inc["state"] == "ARMED":
                        inc["state"], inc["message"] = "CANCELLED", "cancelled by operator"
                log.warning("CANCELLED %s by operator", instance)
                return self._send(200, inc)
            if action == "shutdown_now":
                rt = "ForceOff" if force else inc.get("reset_type", "GracefulShutdown")
                try:
                    msg = do_power(instance, rt)
                    with lock:
                        inc["state"], inc["message"] = "DONE", msg
                    return self._send(200, inc)
                except Exception as e:  # noqa: BLE001
                    return self._send(500, {"error": str(e)})

        # /api/hosts/{instance}/shutdown | poweron
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "hosts":
            instance, action = parts[2], parts[3]
            try:
                if action == "shutdown":
                    rt = "ForceOff" if force else "GracefulShutdown"
                    return self._send(200, {"message": do_power(instance, rt)})
                if action == "poweron":
                    return self._send(200, {"message": do_power(instance, "On")})
            except KeyError as e:
                return self._send(404, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"error": str(e)})

        return self._send(404, {"error": "not found"})


HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>BMC Guardian</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;
--red:#f85149;--amber:#d29922;--green:#3fb950;--blue:#388bfd}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto;
background:var(--bg);color:var(--fg)}
header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:12px}h1{font-size:17px;margin:0;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green)}
main{max-width:880px;margin:0 auto;padding:20px}
.tok{margin-left:auto}.tok input{background:#0d1117;border:1px solid var(--line);
color:var(--fg);border-radius:6px;padding:5px 8px;width:160px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px;margin:0 0 14px}.muted{color:var(--mut)}
.alarm{border-color:var(--red);box-shadow:0 0 0 1px var(--red),0 0 24px #f8514955;
animation:pulse 1s infinite}@keyframes pulse{50%{box-shadow:0 0 0 1px var(--red),0 0 8px #f8514955}}
.count{font-size:40px;font-weight:700;font-variant-numeric:tabular-nums}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
button{border:0;border-radius:7px;padding:9px 14px;font-weight:600;cursor:pointer;color:#fff}
.b-cancel{background:var(--green)}.b-now{background:var(--red)}
.b-soft{background:var(--blue)}.b-force{background:var(--amber);color:#1c1c00}
.b-on{background:#2ea043}.tag{font-size:12px;padding:2px 8px;border-radius:999px;
border:1px solid var(--line);color:var(--mut)}h2{font-size:13px;text-transform:uppercase;
letter-spacing:.05em;color:var(--mut);margin:22px 0 10px}
table{width:100%;border-collapse:collapse}td{padding:8px 6px;border-top:1px solid var(--line)}
code{background:#0d1117;padding:1px 5px;border-radius:4px}
</style></head><body>
<header><span class=dot></span><h1>BMC Guardian</h1>
<span class=tag id=stamp></span>
<span class=tok>token <input id=tok placeholder="if required"></span></header>
<main>
<div id=alerts></div>
<h2>Manual control</h2>
<div class=card><table id=hosts></table>
<p class=muted style=margin:10px>Graceful = clean ACPI shutdown. Force = hard power off (data-loss risk).</p>
</div>
</main>
<script>
const $=s=>document.querySelector(s);
const tokEl=$('#tok'); tokEl.value=localStorage.getItem('gtok')||'';
tokEl.oninput=()=>localStorage.setItem('gtok',tokEl.value);
function hdr(){const t=tokEl.value.trim();return t?{Authorization:'Bearer '+t}:{}}
let actx,lastBeep=0;
function beep(){try{actx=actx||new(window.AudioContext||webkitAudioContext)();
if(performance.now()-lastBeep<900)return;lastBeep=performance.now();
const o=actx.createOscillator(),g=actx.createGain();o.connect(g);g.connect(actx.destination);
o.type='square';o.frequency.value=880;g.gain.value=.06;o.start();
o.stop(actx.currentTime+.18);}catch(e){}}
async function post(u){const r=await fetch(u,{method:'POST',headers:hdr()});
if(!r.ok)alert('error '+r.status+': '+await r.text());return r.ok}
function fmt(s){const m=Math.floor(s/60),x=s%60;return m+':'+String(x).padStart(2,'0')}
async function tick(){
 let d;try{d=await(await fetch('/api/incidents')).json()}catch(e){return}
 $('#stamp').textContent='updated '+new Date().toLocaleTimeString();
 const box=$('#alerts');let html='';let beeping=false;
 if(!d.incidents.length){box.innerHTML='<div class=card><b style=color:var(--green)>All clear.</b> No active incidents.</div>';}
 else{for(const i of d.incidents){
  const armed=i.state==='ARMED';if(armed&&i.auto_shutdown)beeping=true;
  const cls=armed?'card alarm':'card';
  html+=`<div class="${cls}"><div class=row><b>${i.instance}</b>
   <span class=tag>${i.state}</span>${i.dry_run?'<span class=tag>DRY-RUN</span>':''}</div>
   <div class=muted style=margin:4px_0>${i.alertname} — ${i.summary||''}</div>`;
  if(armed){html+=`<div class=count>${i.auto_shutdown?fmt(i.remaining):'warn only'}</div>
   <div class=row><button class=b-cancel onclick="cancel('${i.instance}')">Cancel auto-shutdown</button>
   <button class=b-now onclick="now('${i.instance}',false)">Shut down now</button></div>`;}
  else if(i.message){html+=`<div class=muted>${i.message}</div>`}
  html+='</div>';}}
 box.innerHTML=html;
 if(beeping)beep();
}
async function cancel(h){if(await post('/api/incidents/'+h+'/cancel'))tick()}
async function now(h,f){if(confirm('Shut down '+h+' now?')&&await post('/api/incidents/'+h+'/shutdown_now?force='+f))tick()}
async function mShut(h,f){if(confirm((f?'FORCE power off ':'Shut down ')+h+'?'))await post('/api/hosts/'+h+'/shutdown?force='+f)}
async function mOn(h){if(await post('/api/hosts/'+h+'/poweron'))alert('power-on sent to '+h)}
async function hosts(){const d=await(await fetch('/api/hosts')).json();
 $('#hosts').innerHTML=d.hosts.map(h=>`<tr><td><code>${h}</code></td>
 <td style=text-align:right><div class=row style=justify-content:flex-end>
 <button class=b-soft onclick="mShut('${h}',false)">Graceful</button>
 <button class=b-force onclick="mShut('${h}',true)">Force off</button>
 <button class=b-on onclick="mOn('${h}')">Power on</button></div></td></tr>`).join('');}
hosts();tick();setInterval(tick,1000);
</script></body></html>"""


def main():
    threading.Thread(target=shutdown_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("guardian-controller (stdlib) listening on :%d", PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
