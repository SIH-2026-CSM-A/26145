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

For HTTPS through Caddy (step 4), open 80 and 443 and close 8000 instead. Port 80 must be
open, because Let's Encrypt checks it (HTTP-01 challenge) and Caddy redirects it to 443:

```bash
gcloud compute firewall-rules create sih26145-demo-https --network=default --direction=INGRESS \
  --action=ALLOW --rules=tcp:80,tcp:443 --target-tags=sih26145-demo --source-ranges=0.0.0.0/0
gcloud compute firewall-rules delete sih26145-demo-8000 --quiet
```

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

## 4. Optional: HTTPS with Caddy (no domain needed)

The compose profile `https` adds a Caddy container. It serves the app on 443 with an
automatic Let's Encrypt certificate for `<VM-IP>.sslip.io`. sslip.io is a public DNS service
that answers `34.93.10.20.sslip.io` with `34.93.10.20`, so no domain has to be bought. The host
name comes from `SIH_HOSTNAME`. The config is `deploy/Caddyfile`.

On the VM, in the repository, after the firewall change in step 1:

```bash
docker compose down                                    # if the plain :8000 setup is running
IP=$(curl -s -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)
echo "SIH_HOSTNAME=${IP}.sslip.io"  > .env             # compose reads .env from this directory
echo "SIH_BIND=127.0.0.1"          >> .env             # the app itself only on localhost
docker compose --profile https up -d --build
docker compose logs -f caddy      # wait for "certificate obtained successfully"
curl -sI "https://${IP}.sslip.io/api/v1/health"        # HTTP/2 200
```

Open `https://<VM external IP>.sslip.io`. Notes:
- **What talks out.** Caddy reaches Let's Encrypt to get and renew the certificate. The sensor
  container still sends nothing: the capture is a file in the image. On a real deployment it
  would sit behind the diode with no transmit path, and there would be no Caddy.
- **SSE.** The live alert stream works through `reverse_proxy` with no extra settings: Caddy
  flushes `text/event-stream` responses immediately.
- **Certificates.** They are kept in the `caddy_data` volume, so a restart does not request a
  new one. `docker compose down -v` deletes them.
- **Ephemeral IP.** If the VM's external IP is ephemeral, it changes on stop/start. Reserve a
  static address (`gcloud compute addresses create`) or rewrite `.env` after each start.
- **Stop:** `docker compose --profile https down`.
