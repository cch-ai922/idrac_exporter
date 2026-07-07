"""
guardian-controller
====================
Receives Alertmanager webhooks, runs a cancellable grace-period count-down, and
on expiry issues a Redfish power action (GracefulShutdown by default) to the
affected BMC. Also serves an operator console that beeps + shows the count-down
with Cancel / Shut-down-now buttons, and exposes manual shutdown / power-on.

Single replica only: incident state is in-memory by design so two pods never
both fire a shutdown.
"""
import asyncio
import os
import time
import shlex
import logging
import subprocess
from typing import Optional

import requests
import urllib3
import yaml
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import HTMLResponse, JSONResponse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("guardian")

CONFIG_PATH = os.environ.get("GUARDIAN_CONFIG", "/etc/guardian/config.yaml")
TOKEN = os.environ.get("GUARDIAN_TOKEN", "")  # if set, required on actions/webhook

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("defaults", {})
    cfg.setdefault("hosts", {})
    return cfg

CONFIG = load_config()

def host_policy(instance: str) -> Optional[dict]:
    """Merge defaults + per-host config for a given instance label."""
    hosts = CONFIG.get("hosts", {})
    if instance not in hosts:
        return None
    pol = dict(CONFIG.get("defaults", {}))
    pol.update(hosts[instance] or {})
    pol["instance"] = instance
    return pol

# ---------------------------------------------------------------------------
# Redfish power control (vendor-neutral: Dell iDRAC / Lenovo XCC / Supermicro)
# ---------------------------------------------------------------------------
# Preferred ResetType substitutes when the one we asked for isn't advertised.
# Old Supermicro X11 BMCs (Redfish 1.01) do NOT support GracefulShutdown/PushPowerButton;
# they only expose On / ForceOff / ForceRestart / ForceOn / Nmi. Map accordingly.
_RESET_FALLBACKS = {
    "GracefulShutdown": ["GracefulShutdown", "ForceOff", "PushPowerButton"],
    "ForceOff":         ["ForceOff", "GracefulShutdown", "PushPowerButton"],
    "GracefulRestart":  ["GracefulRestart", "ForceRestart", "PushPowerButton"],
    "ForceRestart":     ["ForceRestart", "GracefulRestart"],
    "On":               ["On", "ForceOn", "PushPowerButton"],
}


def redfish_reset(pol: dict, reset_type: str) -> str:
    """Discover the ComputerSystem and POST a Reset action. Returns a message.

    Handles old Supermicro X11 firmware (Redfish 1.01): if Basic Auth is rejected
    (401) it logs in via SessionService and retries with an X-Auth-Token; if the
    requested ResetType isn't supported it maps to one the BMC actually accepts.
    """
    host = pol["instance"]
    base = f"https://{host}"
    verify = bool(pol.get("verify_tls", False))
    user, pwd = pol["username"], pol["password"]

    s = requests.Session()
    s.auth = (user, pwd)                # Basic Auth first (Dell iDRAC / Lenovo XCC)
    s.verify = verify
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    session_url = [None]               # Redfish session to clean up, if we open one

    def _login_session():
        s.auth = None
        r = s.post(f"{base}/redfish/v1/SessionService/Sessions",
                   json={"UserName": user, "Password": pwd}, timeout=15)
        r.raise_for_status()
        token = r.headers.get("X-Auth-Token")
        if not token:
            raise RuntimeError("session login returned no X-Auth-Token")
        s.headers["X-Auth-Token"] = token
        loc = r.headers.get("Location")
        session_url[0] = loc if (loc or "").startswith("http") else (base + loc if loc else None)
        log.info("%s: authenticated via Redfish session (Basic Auth rejected)", host)

    def req(method, path, **kw):
        """Request with a one-shot Basic->session upgrade on 401."""
        url = path if path.startswith("http") else base + path
        r = s.request(method, url, timeout=kw.pop("timeout", 15), **kw)
        if r.status_code == 401 and "X-Auth-Token" not in s.headers:
            log.warning("%s: 401 on Basic Auth, retrying with session login", host)
            _login_session()
            r = s.request(method, url, timeout=15, **kw)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} {r.reason} {r.text}".strip())
        return r

    try:
        sys_id = pol.get("system_id")
        if sys_id:
            sys_path = f"/redfish/v1/Systems/{sys_id}"
        else:
            members = req("GET", "/redfish/v1/Systems").json().get("Members", [])
            if not members:
                raise RuntimeError("no Redfish systems found")
            sys_path = members[0]["@odata.id"]

        reset = req("GET", sys_path).json().get("Actions", {}).get("#ComputerSystem.Reset", {})
        target = reset.get("target") or f"{sys_path.rstrip('/')}/Actions/ComputerSystem.Reset"
        allowed = reset.get("ResetType@Redfish.AllowableValues")

        if allowed:
            if reset_type not in allowed:
                chosen = next((c for c in _RESET_FALLBACKS.get(reset_type, [reset_type])
                               if c in allowed), None)
                if chosen is None:
                    raise RuntimeError(f"{reset_type} unsupported and no fallback in {allowed}")
                if chosen != reset_type:
                    log.warning("%s: %s not allowed, using %s (allowed=%s)",
                                host, reset_type, chosen, allowed)
                    reset_type = chosen
        elif reset_type == "GracefulShutdown":
            # No allowable list (common on old Supermicro): ForceOff is honored.
            log.warning("%s: no AllowableValues published; using ForceOff for shutdown", host)
            reset_type = "ForceOff"

        r = req("POST", target, json={"ResetType": reset_type}, timeout=30)
        return f"Redfish {reset_type} -> {host} ({r.status_code})"
    finally:
        if session_url[0]:
            try:
                s.delete(session_url[0], timeout=10)   # best-effort session cleanup
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Out-of-band (OOB) shutdown fallback — for BMCs where Redfish can't do a clean
# graceful shutdown (e.g. old Supermicro X11 firmware, Redfish 1.01). Configured
# per host via an "oob_shutdown" block. See config.example / README for keys.
# ---------------------------------------------------------------------------
def _run(cmd, redact=(), timeout=45):
    """Run a subprocess; return (rc, output). `redact` values are masked in logs."""
    shown = " ".join(cmd)
    for secret in redact:
        if secret:
            shown = shown.replace(secret, "***")
    log.info("OOB exec: %s", shown)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found (install it in the image)"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    out = (p.stdout + p.stderr).strip()
    for secret in redact:
        if secret:
            out = out.replace(secret, "***")
    return p.returncode, out


def oob_shutdown(pol: dict, reset_type: str) -> str:
    """Perform an out-of-band shutdown/power action. Returns a message; raises on failure."""
    cfg = pol.get("oob_shutdown") or {}
    method = cfg.get("method", "ipmitool")
    host = pol["instance"]

    if method == "ipmitool":
        ipmi_host = cfg.get("ipmi_host", host)
        user = cfg.get("ipmi_user", pol.get("username"))
        pwd = cfg.get("ipmi_password", pol.get("password"))
        iface = cfg.get("ipmi_interface", "lanplus")
        chassis = {
            "GracefulShutdown": "soft",   # ACPI graceful via BMC
            "GracefulRestart": "cycle",
            "ForceRestart": "reset",
            "ForceOff": "off",
            "On": "on",
        }.get(reset_type, "soft")
        cmd = ["ipmitool", "-I", iface, "-H", ipmi_host, "-U", str(user),
               "-P", str(pwd), "chassis", "power", chassis]
        rc, out = _run(cmd, redact=(str(pwd),))
        if rc != 0:
            raise RuntimeError(f"ipmitool failed (rc={rc}): {out}")
        return f"OOB ipmitool chassis power {chassis} -> {host}: {out or 'ok'}"

    if method == "ssh":
        ssh_host = cfg.get("ssh_host", host)
        user = cfg.get("ssh_user", "root")
        port = str(cfg.get("ssh_port", 22))
        remote = cfg.get("ssh_command") or (
            "reboot" if reset_type in ("GracefulRestart", "ForceRestart") else "shutdown -h now")
        cmd = ["ssh", "-p", port,
               "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", "ConnectTimeout=10"]
        key = cfg.get("ssh_key")
        if key:
            cmd += ["-i", key]
        cmd += [f"{user}@{ssh_host}"] + shlex.split(remote)
        rc, out = _run(cmd)
        # sshd may be torn down by the shutdown before it can reply cleanly (255).
        if rc not in (0, 255):
            raise RuntimeError(f"ssh shutdown failed (rc={rc}): {out}")
        return f"OOB ssh '{remote}' -> {user}@{ssh_host}: {out or 'sent'}"

    raise RuntimeError(f"unknown oob_shutdown method '{method}'")


def do_power(instance: str, reset_type: str) -> str:
    pol = host_policy(instance)
    if not pol:
        raise HTTPException(404, f"unknown host {instance}")
    if pol.get("dry_run"):
        msg = f"[DRY-RUN] would send {reset_type} to {instance}"
        log.warning(msg)
        return msg

    oob = pol.get("oob_shutdown") or {}
    # Power-ON never uses SSH (nothing to log into); ipmitool can, so allow it there.
    oob_applicable = bool(oob) and (reset_type != "On" or oob.get("method") == "ipmitool")

    if oob_applicable and oob.get("prefer"):
        msg = oob_shutdown(pol, reset_type)
        log.warning("POWER ACTION: %s", msg)
        return msg

    try:
        msg = redfish_reset(pol, reset_type)
    except Exception as e:  # noqa: BLE001
        if not oob_applicable:
            raise
        log.warning("%s: Redfish failed (%s) — falling back to OOB %s",
                    instance, e, oob.get("method", "ipmitool"))
        msg = oob_shutdown(pol, reset_type) + f" [redfish fallback: {e}]"
    log.warning("POWER ACTION: %s", msg)
    return msg

# ---------------------------------------------------------------------------
# Incident state machine
#   ARMED -> (cancel) CANCELLED | (resolve) RESOLVED | (timeout) SHUTTING_DOWN -> DONE/FAILED
# ---------------------------------------------------------------------------
incidents: dict[str, dict] = {}   # key = instance

def arm(instance: str, alertname: str, summary: str):
    pol = host_policy(instance)
    if not pol:
        log.warning("alert for unconfigured host %s — ignoring action", instance)
        return
    inc = incidents.get(instance)
    if inc and inc["state"] in ("ARMED", "SHUTTING_DOWN", "DONE"):
        inc["alertname"] = alertname
        inc["summary"] = summary
        return  # already counting down / acted
    grace = int(pol.get("grace_seconds", 120))
    incidents[instance] = {
        "instance": instance,
        "alertname": alertname,
        "summary": summary,
        "state": "ARMED",
        "armed_at": time.time(),
        "shutdown_at": time.time() + grace,
        "grace_seconds": grace,
        "auto_shutdown": bool(pol.get("auto_shutdown", True)),
        "dry_run": bool(pol.get("dry_run", False)),
        "reset_type": pol.get("reset_type", "GracefulShutdown"),
        "message": "",
    }
    log.warning("ARMED %s (%s): shutdown in %ss", instance, alertname, grace)

def resolve(instance: str):
    inc = incidents.get(instance)
    if inc and inc["state"] == "ARMED":
        inc["state"] = "RESOLVED"
        inc["message"] = "alert cleared before timeout"
        log.info("RESOLVED %s", instance)

async def shutdown_loop():
    while True:
        now = time.time()
        for inc in list(incidents.values()):
            if inc["state"] != "ARMED":
                continue
            if now < inc["shutdown_at"]:
                continue
            if not inc["auto_shutdown"]:
                inc["state"] = "RESOLVED"
                inc["message"] = "auto_shutdown disabled — warn only"
                continue
            inc["state"] = "SHUTTING_DOWN"
            try:
                msg = await asyncio.to_thread(do_power, inc["instance"], inc["reset_type"])
                inc["state"] = "DONE"
                inc["message"] = msg
            except Exception as e:  # noqa: BLE001
                inc["state"] = "FAILED"
                inc["message"] = f"shutdown failed: {e}"
                log.error("shutdown FAILED for %s: %s", inc["instance"], e)
        await asyncio.sleep(1)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="bmc-guardian")

@app.on_event("startup")
async def _startup():
    asyncio.create_task(shutdown_loop())

def check_token(authorization: Optional[str]):
    if not TOKEN:
        return
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "invalid or missing token")

@app.get("/healthz")
async def healthz():
    return {"ok": True, "hosts": list(CONFIG.get("hosts", {}).keys())}

@app.post("/webhook")
async def webhook(request: Request, authorization: Optional[str] = Header(None)):
    check_token(authorization)
    payload = await request.json()
    for a in payload.get("alerts", []):
        labels = a.get("labels", {})
        instance = labels.get("instance", "")
        if not instance:
            continue
        status = a.get("status", "firing")
        if status == "resolved":
            resolve(instance)
            continue
        if labels.get("guardian_action") == "shutdown":
            summary = a.get("annotations", {}).get("summary", labels.get("alertname", ""))
            arm(instance, labels.get("alertname", "alert"), summary)
    return {"received": len(payload.get("alerts", []))}

@app.get("/api/incidents")
async def api_incidents():
    now = time.time()
    out = []
    for inc in incidents.values():
        d = dict(inc)
        d["remaining"] = max(0, int(inc["shutdown_at"] - now)) if inc["state"] == "ARMED" else 0
        out.append(d)
    return {"incidents": out, "now": now}

@app.post("/api/incidents/{instance}/cancel")
async def api_cancel(instance: str, authorization: Optional[str] = Header(None)):
    check_token(authorization)
    inc = incidents.get(instance)
    if not inc:
        raise HTTPException(404, "no such incident")
    if inc["state"] == "ARMED":
        inc["state"] = "CANCELLED"
        inc["message"] = "cancelled by operator"
        log.warning("CANCELLED %s by operator", instance)
    return inc

@app.post("/api/incidents/{instance}/shutdown_now")
async def api_shutdown_now(instance: str, force: bool = False,
                           authorization: Optional[str] = Header(None)):
    check_token(authorization)
    inc = incidents.get(instance)
    if not inc:
        raise HTTPException(404, "no such incident")
    rt = "ForceOff" if force else inc.get("reset_type", "GracefulShutdown")
    inc["state"] = "SHUTTING_DOWN"
    msg = await asyncio.to_thread(do_power, instance, rt)
    inc["state"] = "DONE"
    inc["message"] = msg
    return inc

@app.get("/api/hosts")
async def api_hosts():
    return {"hosts": list(CONFIG.get("hosts", {}).keys())}

@app.post("/api/hosts/{instance}/shutdown")
async def api_host_shutdown(instance: str, force: bool = False,
                            authorization: Optional[str] = Header(None)):
    check_token(authorization)
    rt = "ForceOff" if force else "GracefulShutdown"
    return {"message": await asyncio.to_thread(do_power, instance, rt)}

@app.post("/api/hosts/{instance}/poweron")
async def api_host_poweron(instance: str, authorization: Optional[str] = Header(None)):
    check_token(authorization)
    return {"message": await asyncio.to_thread(do_power, instance, "On")}

@app.get("/", response_class=HTMLResponse)
async def console():
    return HTML

# ---------------------------------------------------------------------------
# Operator console (single page; beep + count-down + cancel + manual controls)
# ---------------------------------------------------------------------------
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
 const live=d.incidents.filter(i=>i.state==='ARMED');
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
