#!/usr/bin/env python3
"""Mihomo VPN Manager: terminal-only subscription and domain routing manager."""
import base64
import copy
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit('Missing python3-yaml: apt install python3-yaml')

ROOT = Path('/etc/mihomo-manager')
STATE = ROOT / 'state.json'
CONFIG = Path('/etc/mihomo/config.yaml')
MIHOMO = Path('/usr/local/bin/mihomo')
SERVICE = 'mihomo-manager.service'
UA = 'clash.meta'
MAX_DOWNLOAD = 4 * 1024 * 1024
DEFAULT_VPN = ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com']
PRIVATE_RULES = [
    'DOMAIN-SUFFIX,localhost,DIRECT', 'DOMAIN-SUFFIX,local,DIRECT',
    'DOMAIN-SUFFIX,lan,DIRECT', 'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,169.254.0.0/16,DIRECT,no-resolve',
]
SUPPORTED = {'trojan', 'hysteria2', 'vless', 'ss'}


def shell(args, check=False, **kw):
    return subprocess.run(args, check=check, text=True, **kw)


def write_secret(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(data)
    os.replace(tmp, path)


def load():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding='utf-8'))
    return {'subscription': '', 'nodes': [], 'selected': '', 'rules': [
        {'type': 'DOMAIN-SUFFIX', 'value': domain, 'route': 'VPN'} for domain in DEFAULT_VPN
    ]}


def save(state):
    write_secret(STATE, json.dumps(state, indent=2, ensure_ascii=False))


def safe_b64(value):
    value = re.sub(r'\s+', '', value)
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)).decode('utf-8')


def query_value(query, *keys):
    for key in keys:
        if key in query:
            return query[key][0]
    return ''


def parse_link(link):
    link = link.strip()
    if not link or link.startswith('#'):
        return None
    u = urllib.parse.urlsplit(link)
    typ = u.scheme.lower()
    if typ not in SUPPORTED:
        return None
    q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    name = urllib.parse.unquote(u.fragment) or f'{typ}-{u.hostname or "unknown"}'
    if typ == 'ss':
        # SIP002: ss://base64(method:password)@host:port or full base64 URI
        if not u.hostname:
            raw = safe_b64(u.netloc)
            u = urllib.parse.urlsplit('ss://' + raw + ('#' + u.fragment if u.fragment else ''))
        credentials = urllib.parse.unquote(u.username or '')
        if u.password:
            method, password = credentials, urllib.parse.unquote(u.password)
        else:
            decoded = safe_b64(credentials) if ':' not in credentials else credentials
            method, password = decoded.split(':', 1)
        if not u.hostname or not u.port or not method or not password:
            raise ValueError('invalid Shadowsocks link')
        return {'name': name, 'type': 'ss', 'server': u.hostname, 'port': u.port,
                'cipher': method, 'password': password, 'udp': True}
    node = {'name': name, 'type': typ, 'server': u.hostname, 'port': u.port}
    if not node['server'] or not node['port']:
        raise ValueError('missing host/port')
    if typ == 'trojan':
        node['password'] = urllib.parse.unquote(u.username or '')
        node['sni'] = query_value(q, 'sni', 'peer') or u.hostname
        node['skip-cert-verify'] = query_value(q, 'allowInsecure', 'insecure') == '1'
    elif typ == 'hysteria2':
        node['password'] = urllib.parse.unquote(u.username or '')
        node['sni'] = query_value(q, 'sni', 'peer') or u.hostname
        node['skip-cert-verify'] = query_value(q, 'insecure', 'allowInsecure') == '1'
        if query_value(q, 'obfs') == 'salamander':
            node['obfs'] = 'salamander'
            node['obfs-password'] = query_value(q, 'obfs-password', 'obfsPassword')
    elif typ == 'vless':
        node['uuid'] = urllib.parse.unquote(u.username or '')
        node['tls'] = query_value(q, 'security') in ('tls', 'reality')
        node['servername'] = query_value(q, 'sni', 'serverName') or u.hostname
        node['client-fingerprint'] = query_value(q, 'fp') or 'chrome'
        node['network'] = query_value(q, 'type') or 'tcp'
        node['udp'] = True
        node['skip-cert-verify'] = query_value(q, 'allowInsecure') == '1'
        if query_value(q, 'security') == 'reality':
            node['reality-opts'] = {'public-key': query_value(q, 'pbk'), 'short-id': query_value(q, 'sid')}
        if node['network'] == 'ws':
            node['ws-opts'] = {'path': query_value(q, 'path') or '/', 'headers': {}}
            host = query_value(q, 'host')
            if host:
                node['ws-opts']['headers']['Host'] = host
        elif node['network'] == 'grpc':
            node['grpc-opts'] = {'grpc-service-name': query_value(q, 'serviceName')}
        elif node['network'] not in ('tcp', 'ws', 'grpc'):
            raise ValueError('unsupported VLESS transport ' + node['network'])
        flow = query_value(q, 'flow')
        if flow:
            node['flow'] = flow
    return node


def fetch_subscription(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Subscription URL must be HTTPS without embedded credentials')
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    with urllib.request.urlopen(req, timeout=25) as resp:
        if resp.geturl().split(':', 1)[0] != 'https':
            raise ValueError('Refusing redirect to HTTP')
        raw = resp.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError('Subscription is too large')
    content = raw.decode('utf-8-sig').strip()
    nodes = []
    errors = []
    if 'proxies:' in content[:10000]:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict) or not isinstance(doc.get('proxies'), list):
            raise ValueError('YAML subscription has no proxies list')
        for item in doc['proxies']:
            if isinstance(item, dict) and item.get('type') in SUPPORTED:
                nodes.append(item)
    else:
        if not any(x in content for x in ('://', '\n')):
            content = safe_b64(content)
        for line in content.splitlines():
            try:
                node = parse_link(line)
                if node:
                    nodes.append(node)
            except Exception as exc:
                errors.append(str(exc))
    clean = []
    names = set()
    for node in nodes:
        if not node.get('server') or not node.get('port') or not node.get('name'):
            continue
        node = copy.deepcopy(node)
        name = str(node['name'])
        candidate = name
        i = 2
        while candidate in names or candidate in ('VPN', 'DIRECT', 'REJECT'):
            candidate = f'{name} ({i})'
            i += 1
        node['name'] = candidate
        names.add(candidate)
        clean.append(node)
    if not clean:
        raise ValueError('No supported connections found (or subscription format unsupported)')
    return clean, errors


def generate(state):
    selected = state['selected']
    if not selected or selected not in {x['name'] for x in state['nodes']}:
        raise ValueError('Select an existing VPN node first')
    rules = PRIVATE_RULES.copy()
    for rule in state['rules']:
        typ, val, route = rule['type'], rule['value'], rule['route']
        if typ == 'IP-CIDR':
            rules.append(f'{typ},{val},{route},no-resolve')
        else:
            rules.append(f'{typ},{val},{route}')
    rules.append('MATCH,DIRECT')
    return {'mixed-port': 7890, 'allow-lan': False, 'bind-address': '127.0.0.1',
            'mode': 'rule', 'log-level': 'info', 'ipv6': False,
            'external-controller': '127.0.0.1:9090',
            'proxies': state['nodes'],
            'proxy-groups': [{'name': 'VPN', 'type': 'select', 'proxies': [selected]}],
            'rules': rules}


def apply(state):
    config = yaml.safe_dump(generate(state), allow_unicode=True, sort_keys=False)
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mihomo-test-') as d:
        candidate = Path(d) / 'config.yaml'
        candidate.write_text(config, encoding='utf-8')
        os.chmod(candidate, 0o600)
        result = shell([str(MIHOMO), '-t', '-f', str(candidate)], capture_output=True)
        if result.returncode:
            print('Configuration test failed:\n', (result.stdout + result.stderr)[-2500:])
            return False
    previous = CONFIG.read_bytes() if CONFIG.exists() else None
    if previous is not None:
        backup = CONFIG.with_name('config.yaml.bak')
        write_secret(backup, previous.decode('utf-8'))
    write_secret(CONFIG, config)
    result = shell(['systemctl', 'restart', SERVICE], capture_output=True)
    if result.returncode or shell(['systemctl', 'is-active', '--quiet', SERVICE]).returncode:
        print('Service failed; rolling back configuration.')
        if previous is None:
            CONFIG.unlink(missing_ok=True)
        else:
            write_secret(CONFIG, previous.decode('utf-8'))
        shell(['systemctl', 'restart', SERVICE])
        print((result.stdout + result.stderr)[-1200:])
        return False
    save(state)
    print('Saved and activated successfully.')
    return True


def choose(nodes):
    for i, node in enumerate(nodes, 1):
        print(f' {i:2}. [{node["type"]:9}] {node["name"]} ({node["server"]}:{node["port"]})')
    try:
        n = int(input('Choose number (0=cancel): '))
        return nodes[n-1] if 1 <= n <= len(nodes) else None
    except (ValueError, EOFError):
        return None


def update_subscription(state, new_url=False):
    url = input('Subscription HTTPS URL: ').strip() if new_url else state.get('subscription', '')
    if not url:
        print('No subscription URL saved.')
        return
    try:
        nodes, errors = fetch_subscription(url)
        print(f'Found {len(nodes)} supported nodes; skipped {len(errors)} invalid links.')
        selected = next((x['name'] for x in nodes if x['name'] == state.get('selected')), None)
        if not selected:
            selected_node = choose(nodes)
            if selected_node is None:
                return
            selected = selected_node['name']
        proposed = copy.deepcopy(state)
        proposed.update(subscription=url, nodes=nodes, selected=selected)
        if apply(proposed):
            print('Active node:', selected)
    except Exception as exc:
        print('Subscription error:', exc)


def validate_rule(typ, value):
    if typ == 'IP-CIDR':
        return str(ipaddress.ip_network(value, strict=False))
    value = value.lower().strip().strip('.')
    if value.startswith('*.'):
        value = value[2:]
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', value):
        raise ValueError('Invalid domain')
    if '..' in value or (typ != 'DOMAIN-KEYWORD' and '.' not in value) or (typ != 'DOMAIN-KEYWORD' and any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in value.split('.'))):
        raise ValueError('Invalid domain')
    return value


def add_rule(state):
    print('1. Domain + subdomains  2. Exact domain  3. Domain keyword  4. IP/subnet')
    typ = {'1': 'DOMAIN-SUFFIX', '2': 'DOMAIN', '3': 'DOMAIN-KEYWORD', '4': 'IP-CIDR'}.get(input('Type: ').strip())
    if not typ:
        return
    try:
        value = validate_rule(typ, input('Domain/IP: ').strip())
    except ValueError as exc:
        print(exc)
        return
    route = {'1': 'VPN', '2': 'DIRECT', '3': 'REJECT'}.get(input('1. VPN  2. DIRECT  3. REJECT: ').strip())
    if not route:
        return
    proposed = copy.deepcopy(state)
    proposed['rules'] = [r for r in proposed['rules'] if not (r['type'] == typ and r['value'] == value)]
    proposed['rules'].insert(0, {'type': typ, 'value': value, 'route': route})
    if apply(proposed):
        state.update(proposed)


def remove_rule(state):
    if not state['rules']:
        print('No custom rules')
        return
    for i, r in enumerate(state['rules'], 1):
        print(f'{i}. {r["type"]},{r["value"]},{r["route"]}')
    try:
        n = int(input('Remove number (0=cancel): '))
    except ValueError:
        return
    if not 1 <= n <= len(state['rules']):
        return
    proposed = copy.deepcopy(state)
    proposed['rules'].pop(n-1)
    if apply(proposed):
        state.update(proposed)


def main():
    if os.geteuid() != 0:
        sys.exit('Run with sudo: sudo mihomo-manager')
    if not MIHOMO.exists():
        sys.exit('Mihomo not installed; run install.sh first')
    state = load()
    while True:
        print('\n=== MIHOMO VPN MANAGER ===')
        print('Active:', state.get('selected') or 'not configured')
        print('1. Add/replace subscription  2. Refresh subscription  3. Select VPN node')
        print('4. Add routing rule        5. Remove routing rule  6. Show rules')
        print('7. Show VPN nodes          8. Service status       9. Recent logs')
        print('10. Test proxy request     0. Exit')
        try:
            action = input('> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if action == '0':
            return
        elif action == '1':
            update_subscription(state, True)
            state = load()
        elif action == '2':
            update_subscription(state)
            state = load()
        elif action == '3':
            node = choose(state['nodes'])
            if node:
                proposed = copy.deepcopy(state)
                proposed['selected'] = node['name']
                if apply(proposed):
                    state.update(proposed)
        elif action == '4':
            add_rule(state)
        elif action == '5':
            remove_rule(state)
        elif action == '6':
            for r in state['rules']:
                print(f' {r["type"]},{r["value"]},{r["route"]}')
            print(' MATCH,DIRECT')
        elif action == '7':
            choose(state['nodes'])
        elif action == '8':
            shell(['systemctl', 'status', SERVICE, '--no-pager', '-l'])
        elif action == '9':
            shell(['journalctl', '-u', SERVICE, '-n', '35', '--no-pager'])
        elif action == '10':
            print('Testing ChatGPT via proxy (HTTP response code):')
            shell(['curl', '-sS', '-I', '--max-time', '15', '-x', 'http://127.0.0.1:7890', 'https://chatgpt.com'])
        else:
            print('Unknown option')


if __name__ == '__main__':
    main()
