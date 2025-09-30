# GCP Relay Setup

## Overview

FlareProx can now fall back to a relay that you host on Google Cloud whenever a Cloudflare Worker cannot reach a Cloudflare-managed destination. The relay reuses the same WebSocket handshake as the worker, so no application changes are required—just deploy the relay, note its URL and credentials, then enable it in `flareprox.json` under `client.relay`.

```
"client": {
  "relay": {
    "enabled": true,
    "url": "ws://YOUR_RELAY_HOSTNAME:8080",
    "auth_token": "Bearer YOUR_SHARED_TOKEN",
    "socks_password": "same-password-used-by-worker"
  }
}
```

> **Tips:**
> - Set the relay `socks_password` to match the worker password so the same credential works everywhere.
> - Use `ws://` for plaintext listeners (e.g., a VM without TLS) and `wss://` when you terminate TLS in front of the relay (Cloud Run, HTTPS load balancer, etc.).

---

## Option 1 – Compute Engine VM

1. **Provision the VM**
   - Choose a lightweight image (e.g., `debian-12` or `ubuntu-22.04`).
   - Expose TCP port `8080` (or any port you plan to bind) in the firewall.

2. **Install dependencies**
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-venv git
   python3 -m venv ~/relay-env
   source ~/relay-env/bin/activate
   pip install --upgrade pip
   pip install websockets
   ```

3. **Deploy the relay**
   - Copy `gcp_relay.py` to the VM (e.g., via `git clone` of this repository or `scp`).
   - Run the relay with your chosen password and optional auth token:
     ```bash
     source ~/relay-env/bin/activate
     python3 gcp_relay.py --host 0.0.0.0 --port 8080 \
       --password "YOUR_SHARED_PASSWORD" \
       --auth-token "Bearer YOUR_SHARED_TOKEN"
     ```
   - Keep the process running with `tmux`, `screen`, or a systemd service.

4. **Record the URL**
   - Point a DNS record to the VM or note its external IP: `ws://YOUR_HOST:8080` (use `wss://` only if you terminate TLS in front of the relay).

---

## Option 2 – Cloud Run (Container)

### Prerequisites

1. Access your authorized [Google Cloud Shell](https://shell.cloud.google.com/?hl=en_US&fromcloudshell=true&show=terminal)
2. Pick/create a project and save its ID for the commands below.
3. Configure defaults (replace `PROJECT_ID` and `REGION`, e.g., `us-central1`):
   ```bash
   gcloud config set project PROJECT_ID
   gcloud config set run/region REGION
   ```
4. Enable the required services (one-time per project):
   ```bash
   gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
   ```

### Step 1 – Prepare a build context

From your development machine (where this repo lives):
```bash
mkdir -p cloud-run-relay && cd cloud-run-relay
cp /path/to/repo/gcp_relay.py .
cat <<'EOF' > Dockerfile
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY gcp_relay.py ./
RUN pip install --no-cache-dir websockets
CMD ["python", "gcp_relay.py"]
EOF
```

### Step 2 – Build and publish the container

Cloud Run now prefers Artifact Registry repositories. Create one (once per project), then build:
```bash
gcloud artifacts repositories create flareprox-relay-repo \
  --repository-format docker \
  --location REGION \
  --description "Relay images"

gcloud builds submit --tag REGION-docker.pkg.dev/PROJECT_ID/flareprox-relay-repo/flareprox-relay:latest
```

### Step 3 – Deploy to Cloud Run

```bash
gcloud run deploy flareprox-relay \
  --image REGION-docker.pkg.dev/PROJECT_ID/flareprox-relay-repo/flareprox-relay:latest \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars FLAREPROX_RELAY_PASSWORD=YOUR_SHARED_PASSWORD,FLAREPROX_RELAY_TOKEN="Bearer YOUR_SHARED_TOKEN"
```

- Cloud Run injects the port via `$PORT`; `gcp_relay.py` reads it automatically.
- The deploy command prints a service URL (e.g., `https://relay-xyz.a.run.app`). Use the `wss://` form of that URL inside `flareprox.json`.
- You can re-run the deploy command whenever you push a new image tag.

### Step 4 – Verify the service

1. Fetch the URL anytime:
   ```bash
   gcloud run services describe flareprox-relay --format='value(status.url)'
   ```
2. (Optional) Restrict ingress via:
   ```bash
   gcloud run services update-traffic flareprox-relay --ingress internal-and-cloud-load-balancing
   ```
   Pair this with Cloud Armor or Identity-Aware Proxy if you need more control.

Remember to keep `FLAREPROX_RELAY_PASSWORD`/`TOKEN` strong—Cloud Run treats them like environment variables, and you can rotate them with `gcloud run services update`.

---

## Configure FlareProx Client

1. Open `flareprox.json` (or your chosen config file).
2. In the `client` section, set:
   ```json
   "relay": {
     "enabled": true,
   "url": "ws://relay.example.com:8080",
     "auth_token": "Bearer super-secret-token",
     "socks_password": "generated-socks-password"
   }
   ```
3. Optionally adjust `client.handshake_timeout` (default 5 seconds) if your relay sits behind high-latency networks.
4. Restart any running local SOCKS listeners. FlareProx will now fall back to the relay whenever the worker reports `cloudflare-blocked`.

---

## Verifying the Fallback

1. Run `python3 flareprox.py socks --bind 127.0.0.1`.
2. Access a Cloudflare-hosted site through the SOCKS proxy.
3. When the worker declines the target, the CLI will log a message similar to:
   ```
   flareprox-123: fallback to relay for target.example.com:443 (Target served by Cloudflare IP range)
   ```
4. Confirm the connection succeeds and packets egress from your GCP relay IP (use `https://ifconfig.me/ip`).

If the relay isn’t reachable, FlareProx will return a SOCKS failure to the client—double-check firewall rules, TLS certificates, and credentials.
