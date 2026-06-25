# Running offline / air-gapped

## Runtime: fully offline
After deployment nothing reaches the internet. The controller and exporter talk
only to your BMC IPs (Dell iDRAC / Lenovo XCC / Supermicro) over the local
management network; Prometheus, Alertmanager and Grafana are already in-cluster.
A fault is detected, beeps, counts down and powers off with no outbound traffic.

## Install time: mirror a few images once
Air-gapped Kubernetes always needs images mirrored into an internal registry.
For this project that is just:

1. `ghcr.io/mrlhansen/idrac_exporter:<tag>` — a single static Go binary, easy to
   `docker pull` / `skopeo copy` into your registry. (You don't install any Go
   library; it's one container.)
2. The controller base image (`python:3.12-slim` or any python3 base you already
   mirror).

Then retag the two `image:` fields in the manifests to your internal registry.

## Zero third-party Python libraries: use the stdlib build

There are two controller builds in `controller/`:

| Build | Files | Python deps |
|-------|-------|-------------|
| FastAPI | `app.py`, `Dockerfile`, `requirements.txt`, `guardian-config.example.yaml` | FastAPI, uvicorn, requests, PyYAML (needs pip / a PyPI mirror) |
| **stdlib** | `app_stdlib.py`, `Dockerfile.stdlib`, `config.example.json` | **none — standard library only** |

The stdlib build needs **no `pip install` at all** and runs on any `python3`. It
uses `http.server`, `urllib`, `ssl`, `json`, `threading`. The web console has no
CDN or external JS either. Behaviour is identical (webhook, beep, count-down,
cancel, manual shutdown / power-on, token auth, dry-run).

### Switch the deployment to the stdlib build

Three small changes to the manifests:

1. **Build with the stdlib Dockerfile:**
   ```bash
   docker build -f controller/Dockerfile.stdlib -t YOUR_REGISTRY/guardian-controller:0.1.0-stdlib controller/
   ```
2. **Config as JSON** — in `manifests/40-guardian-secret.yaml`, store the config
   under key `config.json` (copy `controller/config.example.json`) instead of
   `config.yaml`.
3. **Point the env at the JSON file** — in
   `manifests/41-guardian-controller.yaml` set:
   ```yaml
   env:
     - name: GUARDIAN_CONFIG
       value: /etc/guardian/config.json
   ```
   and set the stdlib `image:`.

Everything else (Probe, PrometheusRule, Alertmanager routing, Service,
NetworkPolicy, Ingress) is plain Kubernetes YAML with no dependencies.

> Note: `kube-prometheus-stack` itself (Prometheus, Alertmanager, Grafana) is a
> prerequisite you already run; it's mirror-and-go for air-gap like any other
> chart. This project does not add new internet dependencies beyond the two
> images above.
