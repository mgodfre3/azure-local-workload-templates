#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
[ "$ID" = ubuntu ] && { [ "$VERSION_ID" = 22.04 ] || [ "$VERSION_ID" = 24.04 ]; } || {
    echo "Only a prepared Ubuntu 22.04 or 24.04 LTS image is supported." >&2
    exit 1
}
allowed_cidrs='__ALLOWED_CIDRS__'
[ -n "$allowed_cidrs" ] || { echo "An HTTP client allowlist is required." >&2; exit 1; }
# This dedicated profile owns Nginx configuration, never an existing web server.
owner=/etc/nginx/.azure-local-workloads
if [ -d /etc/nginx ] && [ ! -f "$owner" ]; then
    echo "Unmanaged Nginx configuration exists; refusing to replace it." >&2
    exit 1
fi
apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=180 update -qq
mkdir -p /etc/nginx
touch "$owner"
# Prevent package post-install scripts exposing the default site before ACLs exist.
(
    if [ -e /usr/sbin/policy-rc.d ]; then
        echo "Existing service-start policy requires operator integration; not replacing it." >&2
        exit 1
    fi
    trap 'rm -f /usr/sbin/policy-rc.d' EXIT HUP INT TERM
    printf '%s\n' '#!/bin/sh' 'exit 101' > /usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d
    apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=180 install -y -qq nginx curl rsyslog
)
umask 022
mkdir -p /var/www/azure-local-workloads
printf '%s\n' '<!doctype html><html lang="en"><title>Azure Local web server</title><h1>Nginx is ready</h1></html>' \
    > /var/www/azure-local-workloads/index.html
config=$(mktemp /etc/nginx/.workload.XXXXXX)
trap 'rm -f "$config"' EXIT HUP INT TERM
{
    printf '%s\n' 'server {' '  listen 80 default_server;' '  server_name _;' \
        '  root /var/www/azure-local-workloads;' '  location / {'
    printf '%s\n' '    allow 127.0.0.1;'
    for cidr in $allowed_cidrs; do
        # Defense in depth: do not interpolate unchecked content into Nginx config.
        case "$cidr" in *[!0-9./]*|'') echo "Invalid HTTP CIDR." >&2; exit 1 ;; esac
        printf '    allow %s;\n' "$cidr"
    done
    printf '%s\n' '    deny all;' '    try_files $uri $uri/ =404;' '  }' '}'
} > "$config"
cp "$config" /etc/nginx/sites-available/azure-local-workloads
if [ -e /etc/nginx/sites-enabled/default ] || [ -L /etc/nginx/sites-enabled/default ]; then
    rm /etc/nginx/sites-enabled/default
fi
ln -sfn /etc/nginx/sites-available/azure-local-workloads /etc/nginx/sites-enabled/azure-local-workloads
nginx -t
systemctl enable --now rsyslog
systemctl enable --now nginx
systemctl reload nginx
systemctl is-active --quiet nginx
attempt=0
until curl --fail --silent --max-time 5 http://127.0.0.1/ | grep -q 'Nginx is ready'; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 12 ] || { echo "HTTP readiness failed." >&2; exit 1; }
    sleep 5
done
echo "Nginx is active; local HTTP readiness passed. Remote HTTP is restricted by Nginx CIDR ACLs."
