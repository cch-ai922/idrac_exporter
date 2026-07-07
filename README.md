# BMC Guardian — Controller

Monitors server sensor/fault information via **iDRAC / BMC (Redfish)**, raises an
audible + visual alarm when an anomaly is detected, and **automatically shuts the
server down after a grace period unless an operator cancels it**. Manual
graceful/force shutdown and power-on are also available from the web UI.

The controller is fed by the existing **kube-prometheus + Grafana** stack running
in the Kubernetes cluster: Alertmanager posts sensor-fault alerts to the
controller's `/webhook`, which arms an incident and starts the countdown.

Supported hardware:

- **Dell PowerEdge** (e.g. XE9680) — iDRAC
- **Lenovo** — XClarity Controller (XCC)
- **Supermicro** (e.g. SSG-6049P-E1CR60H) — X11-generation BMC

## Architecture

```text
Prometheus alert  ─►  Alertmanager  ─►  POST /webhook  ─►  arm incident
                                                             │
                                              grace countdown (default 120s)
                                                             │
                                    operator cancels?  ──No──►  Redfish reset (shutdown)
                                          │Yes
                                       RESOLVED
```

- Single replica by design — incident state is in-memory.
- Stdlib-only build: `app_stdlib.py` uses just the Python standard library
  (`http.server`, `urllib`, `ssl`, `json`, `threading`). No `pip install`; runs on
  any `python3`. Config is JSON. See [`OFFLINE.md`](OFFLINE.md) for the air-gapped
  image build.

### Key files

There are two equivalent builds of the controller — same behavior, same fix:

- **`app_stdlib.py`** — standard-library only, JSON config. Preferred for
  air-gapped deploys (no `pip install`).
- **`app.py`** — FastAPI + `requests`, YAML config.

| File | Purpose |
| --- | --- |
| [`app_stdlib.py`](app_stdlib.py) | Stdlib controller: Redfish power control, OOB fallback, incident state machine, HTTP API + web UI. |
| [`app.py`](app.py) | FastAPI controller (same features, YAML config, `requests`). |
| [`config.example.json`](config.example.json) | Sample config for `app_stdlib.py`. Mounted at `/etc/guardian/config.json`. Host keys **must equal** the Prometheus `instance` label (the BMC IP). |
| [`guardian-config.example.yaml`](guardian-config.example.yaml) | Sample config for `app.py`. Mounted at `/etc/guardian/config.yaml`. |
| [`Dockerfile.stdlib`](Dockerfile.stdlib) | Container image for the stdlib build. |
| [`manifests/`](manifests/) | Kubernetes manifests for the monitoring side (idrac_exporter Deployment/Service, its credentials Secret, and the Prometheus `Probe`). |
| [`OFFLINE.md`](OFFLINE.md) | Offline / air-gapped deployment notes. |

## Monitoring side: idrac_exporter and the Supermicro

Sensor/fault data comes from **[`mrlhansen/idrac_exporter`](https://github.com/mrlhansen/idrac_exporter)
(v2.6.1)** — a multi-target Redfish exporter. Prometheus scrapes it via a `Probe`
(one target per BMC); each target's metrics carry `instance=<BMC IP>`, which is the
key the alert rules and the controller share.

### Why the exporter couldn't read the Supermicro

The real cause is a **Supermicro Redfish licensing gate**, not auth or exporter
config. On the Supermicro (`SSG-6049P-E1CR60H`, X11 BMC, IP `10.20.0.20`) a plain
`GET https://10.20.0.20/redfish/v1` returns:

```text
Base.1.0.0.OemLicenseNotPassed
```

Supermicro locks the Redfish **data** API (sensors, power, health — everything the
exporter reads) behind a paid license key (**SFT-OOB-LIC** / SFT-DCMS-Single),
activated per BMC. Without it, the BMC refuses to serve Redfish data. idrac_exporter
does a discovery call on first contact; that call hits the license-gated endpoint,
gets `OemLicenseNotPassed` instead of valid JSON, and can't build its client — which
surfaces as:

```text
500 Internal Server Error
Error instantiating metrics collector for host 10.20.0.20: failed to instantiate new client
```

Dell and Lenovo don't gate Redfish this way, so they work. **No exporter/auth config
can bypass this** — the data simply isn't served without the license.

### The fix: monitor the Supermicro over IPMI instead of Redfish

IPMI sensor reads (temperature, fan, voltage, PSU draw) are **not** license-gated on
these boards. So the Supermicro is scraped with
**[`prometheus-community/ipmi_exporter`](https://github.com/prometheus-community/ipmi_exporter)
(v1.10.1)** instead of idrac_exporter. Dell and Lenovo stay on idrac_exporter,
unchanged.

| Manifest | Role |
| --- | --- |
| [`13-ipmi-exporter-secret.yaml`](manifests/13-ipmi-exporter-secret.yaml) | IPMI credentials + `supermicro` module (collectors: ipmi/chassis/dcmi). |
| [`14-ipmi-exporter.yaml`](manifests/14-ipmi-exporter.yaml) | ipmi_exporter Deployment + Service (port 9290). |
| [`15-ipmi-exporter-probe.yaml`](manifests/15-ipmi-exporter-probe.yaml) | `Probe` scraping `10.20.0.20` → `job="ipmi"`, `instance=10.20.0.20`. |
| [`21-prometheusrule-ipmi.yaml`](manifests/21-prometheusrule-ipmi.yaml) | Alert rules on `ipmi_*` metrics, mirroring the idrac rules incl. `guardian_action: shutdown`. |

Two consequences worth noting:

- **The alert rules had to be duplicated.** The originals key on `idrac_*` metric
  names; IPMI emits `ipmi_*` (e.g. `ipmi_sensor_state`, `ipmi_temperature_celsius`,
  `ipmi_fan_speed_rpm`). `21-prometheusrule-ipmi.yaml` reproduces the same
  warn/critical model on those names, so a critical sensor still arms the shutdown
  countdown for `instance=10.20.0.20`.
- **The Supermicro was removed from the idrac Probe/Secret**
  ([`12`](manifests/12-idrac-exporter-probe.yaml) / [`10`](manifests/10-idrac-exporter-secret.yaml))
  so idrac_exporter stops throwing the 500 and firing false `BMCUnreachable{job="idrac"}`.
- **Power control also uses IPMI for this host.** Redfish reset is license-gated too,
  so in the controller config the Supermicro (`10.20.0.20`) sets
  `oob_shutdown.prefer: true` — it goes straight to `ipmitool` and skips the dead
  Redfish path.

> Alternative: buy + activate an **SFT-OOB-LIC** key on the BMC
> (`POST /redfish/v1/Managers/1/LicenseManager/ActivateLicense`). Then Redfish works
> and you could move the host back onto idrac_exporter. The IPMI path avoids that
> cost and works offline.

### How to confirm

```bash
# The BMC itself — does Redfish still report the license error?
curl -sk https://10.20.0.20/redfish/v1 | grep -i license

# Does the IPMI exporter return sensor metrics for the Supermicro?
kubectl -n bmc-guardian exec deploy/ipmi-exporter -- \
  wget -qO- 'http://localhost:9290/metrics?target=10.20.0.20&module=supermicro' | grep ipmi_ | head

# Prometheus should show up=1 for the ipmi job:
#   up{job="ipmi", instance="10.20.0.20"} == 1
```

### Offline deployment (air-gapped)

**Both exporter images are already bundled** as saved container tarballs — no
download needed:

- [`idrac_exporter/idrac_exporter.tar`](idrac_exporter/) — `ghcr.io/mrlhansen/idrac_exporter:2.6.1` (Dell/Lenovo)
- [`idrac_exporter/ipmi_exporter.tar`](idrac_exporter/) — `quay.io/prometheuscommunity/ipmi-exporter:v1.10.1` (Supermicro)

Load them into your cluster's runtime and apply the manifests — no internet required:

```bash
# 1. Load BOTH images on every node (or push to a local registry).
#    containerd (most Kubernetes):
sudo ctr -n k8s.io images import idrac_exporter/idrac_exporter.tar
sudo ctr -n k8s.io images import idrac_exporter/ipmi_exporter.tar
#    Docker:
#    docker load -i idrac_exporter/idrac_exporter.tar
#    docker load -i idrac_exporter/ipmi_exporter.tar

# 2. Apply the monitoring manifests (both exporters, Secrets, Probes, alert rules).
kubectl apply -f manifests/

# 3. Roll the exporters so they pick up the config.
kubectl -n bmc-guardian rollout restart deploy/idrac-exporter deploy/ipmi-exporter
```

Each Deployment pins an exact tag (never `:latest`), so Kubernetes uses the image you
loaded and never reaches the internet — pinning is what makes the offline path work.
The image tag in the manifest **must match the RepoTag inside the tar** (verify with
`./crane.exe manifest <tar>` or `tar -xO manifest.json`). The `crane.exe` /
`crane.tar.gz` in [`idrac_exporter/`](idrac_exporter/) are the helpers used to pull
these tars on a connected machine and to load/push them air-gapped. See
[`OFFLINE.md`](OFFLINE.md) for the controller image.

> To refresh or re-pull an exporter image on a connected machine (example):
> `./crane.exe pull --platform linux/amd64 quay.io/prometheuscommunity/ipmi-exporter:v1.10.1 ipmi_exporter.tar`
>
> Note: the [`manifests/`](manifests/) folder is the source of truth for the
> monitoring side. The copy inside `bmc-guardian.zip` is an older snapshot; deploy
> from `manifests/`, not from the zip.

## Configuration

Host keys are the BMC IPs and must match the Prometheus `instance` label.

```jsonc
{
  "defaults": {
    "dry_run": true,             // true = log the action, don't actually send it
    "auto_shutdown": true,       // false = warn only, never auto power-off
    "grace_seconds": 120,        // countdown before auto-shutdown
    "reset_type": "GracefulShutdown",
    "verify_tls": false,         // BMC certs are usually self-signed
    "system_id": null            // set to skip Systems-collection discovery
  },
  "hosts": {
    "192.168.10.11": { "username": "guardian", "password": "…", "grace_seconds": 180 },  // Dell
    "192.168.10.12": { "username": "guardian", "password": "…" },                        // Lenovo
    "192.168.10.13": { "username": "guardian", "password": "…" }                         // Supermicro
  }
}
```

## The Supermicro access problem (and the fix)

**Symptom:** everything worked except the Supermicro server
(`SSG-6049P-E1CR60H`, BMC firmware `1.76.30`, BIOS `3.4`, **Redfish version 1.01**,
CPLD `03.b1.02`). The controller could reach Dell and Lenovo but not Supermicro.

**Root cause:** Redfish `1.01` on this X11-generation BMC is an old, partial Redfish
implementation. Three assumptions in the original `redfish_reset` were true for
Dell iDRAC and Lenovo XCC but false for this Supermicro firmware:

1. **Basic Auth is often rejected (HTTP 401).**
   The controller only ever sent `Authorization: Basic …`. Dell and Lenovo accept
   it; X11 BMCs around fw `1.7x` frequently reject Basic Auth on Redfish and
   require a **session token** obtained from
   `POST /redfish/v1/SessionService/Sessions` (returned in the `X-Auth-Token`
   header). This alone explains "only Supermicro fails."

2. **`GracefulShutdown` is not a supported ResetType.**
   Old Supermicro Redfish typically exposes only
   `On / ForceOff / ForceRestart / ForceOn / Nmi`. The original code sent
   `GracefulShutdown` whenever the BMC published no `AllowableValues`, which this
   firmware rejects with **HTTP 400**.

3. **Reset action target / shape differs.**
   The `#ComputerSystem.Reset` action's `target` and
   `ResetType@Redfish.AllowableValues` may be missing or shaped differently, and
   the `target` can be an absolute URL, so the hard-coded fallback path could miss.

Additionally, the original code let `HTTPError` bubble up **without the response
body**, so failures showed an opaque status code with no reason.

### What the fix does

Changes are in [`app_stdlib.py`](app_stdlib.py) (`redfish_reset` and helpers).
Dell and Lenovo behavior is **unchanged** — the new paths only trigger on the
conditions that old Supermicro firmware creates.

1. **Basic → Session-token auth fallback.**
   Requests start with Basic Auth. If any request returns **401**, the controller
   automatically logs in via `POST /redfish/v1/SessionService/Sessions`, captures
   the `X-Auth-Token`, and retries with that header. The session is cleaned up with
   a `DELETE` at the end (old BMCs have small session tables — leaked sessions
   eventually lock the account out).

2. **ResetType negotiation for firmware without `GracefulShutdown`.**
   - If the BMC publishes `AllowableValues` and the requested type isn't in it, the
     controller maps it through a fallback table
     (e.g. `GracefulShutdown → ForceOff`).
   - If the BMC publishes **no** allowable list, a `GracefulShutdown` request is
     downgraded to `ForceOff`, which these BMCs actually honor — instead of blindly
     sending an unsupported type and getting a 400.

3. **Robust action/target discovery.**
   Handles a missing/absolute `target`, strips trailing slashes, and falls back to
   `…/Actions/ComputerSystem.Reset`.

4. **Error visibility.**
   HTTP errors now include the Redfish response body (the
   `@Message.ExtendedInfo` reason) in the exception, so the UI's "error NNN" popup
   and the pod logs show the real cause.

### How to confirm the fix

1. Ensure the Supermicro account for `192.168.10.13` is a Redfish-capable BMC user
   with **Administrator** privileges.
2. From the web UI, trigger a manual **Graceful** shutdown against the Supermicro
   host and watch the controller pod logs. You'll see one of:
   - `authenticated via Redfish session (Basic Auth rejected)` → it was the auth
     issue; now fixed.
   - `no AllowableValues published; using ForceOff` → it was the ResetType issue;
     now handled.
   - `HTTP 4xx … <body>` → a clear message showing exactly what's left.

### Important caveat: graceful shutdown on old Supermicro

A **clean ACPI (graceful) shutdown may not be available at all** through Redfish on
this firmware — `ForceOff` is a hard power-cut (data-loss risk, same as the UI's
"Force off" button). For a genuinely clean shutdown of that box, use the
out-of-band fallback below (or update the BMC firmware — later X11 Redfish builds
add `GracefulShutdown`).

## Out-of-band (OOB) shutdown fallback

For hosts where Redfish can't perform a clean shutdown, each host may declare an
`oob_shutdown` block. When present, `do_power` will:

1. If `prefer: true`, use the OOB method directly (skip Redfish).
2. Otherwise try **Redfish first**, and **fall back to OOB** only if Redfish fails.

Power-**on** stays on Redfish (SSH can't reach a powered-off OS); `ipmitool` power-on
is still allowed when the method is `ipmitool`.

Two methods are supported:

**`ipmitool`** — out-of-band via the BMC's IPMI interface. `GracefulShutdown` maps
to `chassis power soft` (ACPI soft-off, the clean shutdown these BMCs *can* do out
of band), `ForceOff → off`, `ForceRestart → reset`, `On → on`.

```jsonc
"192.168.10.13": {
  "username": "guardian", "password": "…",
  "oob_shutdown": {
    "method": "ipmitool",
    "prefer": false,                 // true = OOB before Redfish
    "ipmi_host": "192.168.10.13",    // defaults to the instance IP
    "ipmi_user": "ADMIN", "ipmi_password": "…", "ipmi_interface": "lanplus"
  }
}
```

**`ssh`** — clean OS-level shutdown by running a command on the host itself (use the
OS/data-network IP, not the BMC). Key-based auth only (`BatchMode=yes`).

```jsonc
"oob_shutdown": {
  "method": "ssh",
  "ssh_host": "10.0.0.13", "ssh_user": "root", "ssh_port": 22,
  "ssh_key": "/etc/guardian/keys/smc",
  "ssh_command": "shutdown -h now"   // optional; defaults per reset_type
}
```

**Requirements:** the chosen binary must be present in the controller image
(`ipmitool` or the `ssh` client), and for `ssh` the private key must be mounted and
the host's OS must trust the corresponding public key. Passwords are masked in logs.
For YAML (`app.py`), the same block goes under the host in
[`guardian-config.example.yaml`](guardian-config.example.yaml).

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Web UI |
| `GET` | `/healthz` | Health + configured hosts |
| `GET` | `/api/hosts` | List configured hosts |
| `GET` | `/api/incidents` | Current incidents + remaining countdown |
| `POST` | `/webhook` | Alertmanager webhook (arm/resolve incidents) |
| `POST` | `/api/incidents/{instance}/cancel` | Cancel an armed auto-shutdown |
| `POST` | `/api/incidents/{instance}/shutdown_now?force=true\|false` | Shut down an incident host now |
| `POST` | `/api/hosts/{instance}/shutdown?force=true\|false` | Manual graceful/force shutdown |
| `POST` | `/api/hosts/{instance}/poweron` | Manual power-on |

Auth: if `GUARDIAN_TOKEN` is set, all endpoints except `GET` pages require
`Authorization: Bearer <token>`.

### Environment variables

| Var | Default | Meaning |
| --- | --- | --- |
| `GUARDIAN_CONFIG` | `/etc/guardian/config.json` | Config file path |
| `GUARDIAN_TOKEN` | *(empty)* | Bearer token for the API/UI (empty = no auth) |
| `GUARDIAN_PORT` | `8080` | Listen port |

## Incident states

`ARMED` → countdown running · `SHUTTING_DOWN` → power action in flight ·
`DONE` → power action sent · `CANCELLED` → operator cancelled ·
`RESOLVED` → alert cleared (or `auto_shutdown` disabled = warn-only) ·
`FAILED` → power action errored (see `message`).
