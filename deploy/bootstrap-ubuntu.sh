#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes ca-certificates certbot curl nginx python3-certbot-nginx

id openai-lb >/dev/null 2>&1 || useradd \
  --system \
  --home-dir /var/lib/openai-lb \
  --shell /usr/sbin/nologin \
  openai-lb

install -d -m 0755 /opt/openai-lb/releases
install -d -o openai-lb -g openai-lb -m 0700 /var/lib/openai-lb

install -m 0644 /dev/stdin /etc/systemd/system/openai-lb.service <<'UNIT'
[Unit]
Description=OpenAI-LB
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openai-lb
Group=openai-lb
Environment=HOME=/var/lib/openai-lb
WorkingDirectory=/var/lib/openai-lb
ExecStart=/opt/openai-lb/current/openai-lb
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/var/lib/openai-lb

[Install]
WantedBy=multi-user.target
UNIT

install -m 0644 /dev/stdin /etc/nginx/sites-available/openai-lb <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name openai.ntnl.io;

    client_max_body_size 512m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

ln -sfn /etc/nginx/sites-available/openai-lb /etc/nginx/sites-enabled/openai-lb
rm -f /etc/nginx/sites-enabled/default
systemctl daemon-reload
systemctl enable openai-lb.service
nginx -t
systemctl restart nginx
