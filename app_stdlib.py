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
import shlex
import logging
import threading
import subprocess
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


def _read_err(e):
    """Extract a useful message + body from an HTTPError."""
    try:
        body = e.read().decode(errors="replace")
    except Exception:  # noqa: BLE001
        body = ""
    return f"HTTP {e.code} {e.reason} {body}".strip()


def redfish_reset(pol, reset_type):
    host = pol["instance"]
    base = "https://" + host
    ctx = _ctx(bool(pol.get("verify_tls", False)))
    user, pwd = pol["username"], pol["password"]
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()

    # Auth state: start with Basic; switch to a Redfish session token on 401.
    # Supermicro X11 (fw ~1.7x) often rejects Basic Auth and requires a session.
    state = {"token": None, "session_path": None}

    def _headers():
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if state["token"]:
            h["X-Auth-Token"] = state["token"]
        else:
            h["Authorization"] = "Basic " + auth
        return h

    def _session_login():
        body = json.dumps({"UserName": user, "Password": pwd}).encode()
        req = urllib.request.Request(
            base + "/redfish/v1/SessionService/Sessions", data=body,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            token = r.getheader("X-Auth-Token")
            loc = r.getheader("Location")
            if not token:
                raise RuntimeError("session login returned no X-Auth-Token")
            state["token"] = token
            # Location may be absolute; store just the path for logout.
            state["session_path"] = urlparse(loc).path if loc else None
        log.info("%s: authenticated via Redfish session (Basic Auth rejected)", host)

    def _session_logout():
        if not state["session_path"]:
            return
        try:
            req = urllib.request.Request(
                base + state["session_path"],
                headers={"X-Auth-Token": state["token"]}, method="DELETE")
            urllib.request.urlopen(req, timeout=10, context=ctx).close()
        except Exception:  # noqa: BLE001
            pass  # best-effort cleanup

    def _open(path, data=None, method="GET"):
        """Open a request, transparently upgrading Basic->session on 401 once."""
        for attempt in (1, 2):
            req = urllib.request.Request(base + path, data=data,
                                         headers=_headers(), method=method)
            try:
                return urllib.request.urlopen(
                    req, timeout=(30 if method == "POST" else 15), context=ctx)
            except urllib.error.HTTPError as e:
                if e.code == 401 and not state["token"] and attempt == 1:
                    log.warning("%s: 401 on Basic Auth, retrying with session login", host)
                    _session_login()
                    continue
                raise RuntimeError(_read_err(e)) from None

    def get(path):
        with _open(path) as r:
            return json.loads(r.read().decode())

    try:
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
        target = reset.get("target") or (sys_path.rstrip("/") + "/Actions/ComputerSystem.Reset")
        allowed = reset.get("ResetType@Redfish.AllowableValues")

        # Pick a ResetType this BMC actually supports.
        if allowed:
            if reset_type not in allowed:
                chosen = next((c for c in _RESET_FALLBACKS.get(reset_type, [reset_type])
                               if c in allowed), None)
                if chosen is None:
                    raise RuntimeError(
                        f"{reset_type} unsupported and no fallback in {allowed}")
                if chosen != reset_type:
                    log.warning("%s: %s not allowed, using %s (allowed=%s)",
                                host, reset_type, chosen, allowed)
                    reset_type = chosen
        else:
            # No allowable list published (common on old Supermicro). If the caller
            # asked for GracefulShutdown, prefer ForceOff which these BMCs do honor.
            if reset_type == "GracefulShutdown":
                log.warning("%s: no AllowableValues published; using ForceOff for shutdown", host)
                reset_type = "ForceOff"

        target_path = urlparse(target).path if target.startswith("http") else target
        body = json.dumps({"ResetType": reset_type}).encode()
        with _open(target_path, data=body, method="POST") as r:
            return f"Redfish {reset_type} -> {host} ({r.status})"
    finally:
        _session_logout()

# ---------------------------------------------------------------------------
# Out-of-band (OOB) shutdown fallback — for BMCs where Redfish can't do a clean
# graceful shutdown (e.g. old Supermicro X11 firmware, Redfish 1.01).
#
# Configured per host via an "oob_shutdown" block, e.g.:
#   "oob_shutdown": {
#     "method": "ipmitool",              # or "ssh"
#     "prefer": false,                   # true = try OOB before Redfish
#     # --- ipmitool ---
#     "ipmi_host": "192.168.10.13",      # defaults to the instance IP
#     "ipmi_user": "ADMIN", "ipmi_password": "…", "ipmi_interface": "lanplus",
#     # --- ssh (shut the OS down cleanly) ---
#     "ssh_host": "10.0.0.13", "ssh_user": "root", "ssh_port": 22,
#     "ssh_key": "/etc/guardian/keys/smc", "ssh_command": "shutdown -h now"
#   }
# Only graceful/off actions use OOB; power-ON stays on Redfish (a powered-off
# host has no OS to SSH into, and ipmitool power on is handled here too).
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


def oob_shutdown(pol, reset_type):
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


def do_power(instance, reset_type):
    pol = host_policy(instance)
    if not pol:
        raise KeyError("unknown host " + instance)
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
