#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then echo 'Run as root: sudo bash install.sh'; exit 1; fi
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -f "$SCRIPT_DIR/manager.py" ]]; then echo 'manager.py not found next to install.sh'; exit 1; fi
# Never replace a running or pre-existing Mihomo installation.
if [[ -e /usr/local/bin/mihomo || -e /etc/systemd/system/mihomo-manager.service || -e /etc/mihomo/config.yaml ]] || systemctl is-active --quiet mihomo.service 2>/dev/null; then
  echo 'Existing Mihomo binary, configuration or service detected. Installation cancelled to protect it.'
  echo 'Use a clean test VM. Existing installations require a manual migration.'
  exit 1
fi
if ss -ltn 2>/dev/null | grep -qE '(:|\])7890[[:space:]]'; then
  echo 'Port 7890 is already occupied; refusing to install.'
  exit 1
fi
if ! command -v apt-get >/dev/null; then echo 'Debian/Ubuntu only'; exit 1; fi
arch=$(dpkg --print-architecture)
case "$arch" in
  amd64) pattern='mihomo-linux-amd64-compatible-.*\.gz$' ;;
  arm64) pattern='mihomo-linux-arm64-.*\.gz$' ;;
  *) echo "Unsupported architecture: $arch"; exit 1 ;;
esac
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl python3 python3-yaml
python3 - "$pattern" <<'PY'
import json, os, re, shutil, sys, tempfile, urllib.request, gzip
pattern = re.compile(sys.argv[1])
req = urllib.request.Request('https://api.github.com/repos/MetaCubeX/mihomo/releases/latest',headers={'User-Agent':'mihomo-vpn-manager'})
with urllib.request.urlopen(req,timeout=25) as r:
    assets=json.load(r)['assets']
urls=[a['browser_download_url'] for a in assets if pattern.search(a['name'])]
if not urls:
    sys.exit('No compatible Mihomo binary in latest release; check GitHub releases')
url=urls[0]
print('Downloading:',url)
with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'mihomo-vpn-manager'}),timeout=90) as r:
    data=r.read(120*1024*1024+1)
if len(data)>120*1024*1024:
    sys.exit('Download exceeds limit')
binary=gzip.decompress(data)
with tempfile.NamedTemporaryFile(dir='/usr/local/bin',delete=False) as f:
    f.write(binary)
    name=f.name
os.chmod(name,0o755)
os.replace(name,'/usr/local/bin/mihomo')
PY
/usr/local/bin/mihomo -v
install -d -m 700 /etc/mihomo-manager
install -d -m 700 /etc/mihomo
install -m 755 "$SCRIPT_DIR/manager.py" /usr/local/bin/mihomo-manager
cat > /etc/systemd/system/mihomo-manager.service <<'EOF'
[Unit]
Description=Mihomo VPN Manager local proxy
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable mihomo-manager.service
if [[ -f /etc/mihomo/config.yaml ]]; then
  echo 'Existing /etc/mihomo/config.yaml found. Leaving it unchanged.'
  echo 'WARNING: port 7890 may already be in use by another Mihomo instance.'
else
  echo 'No existing config; manager will generate one after subscription import.'
fi
echo 'Installed. Start with: sudo mihomo-manager'
