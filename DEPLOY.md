# Deploying the demo on an Ubuntu VM (GCP)

The image replays the committed demo capture (`demo/demo.pcap`) through the real pipeline, in a
loop at 2× real time, and serves the dashboard and read-only API on port 8000.
- **No network at runtime.** Models, dashboard and capture are baked in, and the page loads
  nothing from another origin.
- **No auth.** Every route is GET, and any other method gets 405. There is no upload, analyze,
  reset or write endpoint.

Tested locally with Docker Desktop 4.x. The commands below are for Ubuntu 22.04/24.04 on a
Compute Engine VM, e2-standard-2 or larger: the pipeline uses one core.

## 1. VM and firewall (from your machine, with gcloud)

```bash
gcloud compute instances create sih26145-demo --zone=asia-south1-a --machine-type=e2-standard-2 \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=20GB \
  --tags=sih26145-demo
gcloud compute firewall-rules create sih26145-demo-8000 --network=default --direction=INGRESS \
  --action=ALLOW --rules=tcp:8000 --target-tags=sih26145-demo --source-ranges=0.0.0.0/0
gcloud compute ssh sih26145-demo --zone=asia-south1-a
```

With HTTPS through Caddy (step 4), open 80 and 443 instead of 8000:
`--rules=tcp:80,tcp:443`.

## 2. Docker (on the VM, official apt repository)

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER" && newgrp docker
```

## 3. Build and run

```bash
git clone https://github.com/SIH-2026-CSM-A/26145.git && cd 26145
sha256sum demo/demo.pcap   # must print ba44d087e800be6df0befdde5a7fb241073c9bfa01174b87949f6ea6d1a756f0
docker compose up -d --build
docker compose logs -f sensor     # "replaying /app/demo/demo.pcap (2.0x real time), loop 1"
curl -s http://127.0.0.1:8000/api/v1/health
```

Open `http://<VM external IP>:8000`.
- **Speed.** One loop takes about 5.5 minutes at 2×, then the final picture is held for 30 s,
  and the next loop starts from an empty store; dashboards clear on the reset. To change the
  speed, override the command in `docker-compose.yml`, for example
  `command: ["sih26145", "serve", "/app/demo/demo.pcap", "--speed", "5", "--loop", "--host", "0.0.0.0"]`.
- **Hardening.** The container runs as a non-root user (`sih`) with a read-only root file system,
  all capabilities dropped and `no-new-privileges`.
- **Stop:** `docker compose down`.

## 4. Optional: HTTPS with Caddy (needs a DNS name pointing at the VM)

```bash
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update && sudo apt-get install -y caddy
echo 'demo.example.org {
  reverse_proxy 127.0.0.1:8000
}' | sudo tee /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy obtains and renews the certificate itself. The SSE stream (`/api/v1/stream/alerts`) works
through `reverse_proxy` without extra settings. When Caddy fronts the app, bind the container to
localhost only: set `ports: ["127.0.0.1:8000:8000"]` in `docker-compose.yml`, and close port
8000 in the firewall.
