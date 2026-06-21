"""OPNsense REST API client. No print/exit here - callers handle output and errors."""

import base64
import ipaddress
import json
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

CACHE_DIR = Path(os.environ.get("TMPDIR", tempfile.gettempdir()))
RULE_INDEX_FILE = CACHE_DIR / ".opnsense_rule_index.json"
LEASE_INDEX_FILE = CACHE_DIR / ".opnsense_lease_index.json"
RESERVATION_INDEX_FILE = CACHE_DIR / ".opnsense_reservation_index.json"

ALIAS_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
MAC_RE = re.compile(r"^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}$")


class LazySenseError(Exception):
    pass


class Config:
    def __init__(self):
        self.host = os.environ.get("OPNSENSE_HOST", "192.168.1.1")
        self.port = os.environ.get("OPNSENSE_PORT", "443")
        self.key = os.environ.get("OPNSENSE_KEY", "")
        self.secret = os.environ.get("OPNSENSE_SECRET", "")
        self.insecure = os.environ.get("OPNSENSE_INSECURE", "true").lower() == "true"
        self.domain = os.environ.get("OPNSENSE_DOMAIN", "")

        if not self.key:
            creds_file = Path.home() / ".opnsense" / "credentials"
            if creds_file.is_file():
                self._load_credentials(creds_file)

    def _load_credentials(self, path):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key == "OPNSENSE_HOST":
                self.host = value
            elif key == "OPNSENSE_PORT":
                self.port = value
            elif key == "OPNSENSE_KEY":
                self.key = value
            elif key == "OPNSENSE_SECRET":
                self.secret = value
            elif key == "OPNSENSE_INSECURE":
                self.insecure = value.lower() == "true"
            elif key == "OPNSENSE_DOMAIN":
                self.domain = value

    @property
    def base_url(self):
        return f"https://{self.host}:{self.port}"

    def validate(self):
        if not self.key or not self.secret:
            raise LazySenseError(
                "API credentials not configured. "
                "Set OPNSENSE_KEY/OPNSENSE_SECRET or create ~/.opnsense/credentials"
            )

    def __repr__(self):
        return f"Config(host={self.host!r}, port={self.port!r}, key='***', secret='***')"


def _ssl_context(config):
    if config.insecure:
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context()
    return ctx


def _auth_header(config):
    token = base64.b64encode(f"{config.key}:{config.secret}".encode()).decode()
    return f"Basic {token}"


def request(config, method, endpoint, data=None):
    config.validate()
    url = f"{config.base_url}{endpoint}"
    headers = {"Authorization": _auth_header(config), "Accept": "application/json"}
    body = None
    if method == "POST":
        body = json.dumps(data if data is not None else {}).encode()
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_ssl_context(config)) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        return exc.read()
    except urllib.error.URLError as exc:
        raise LazySenseError(f"request to {url} failed: {exc.reason}") from exc


def get_raw(config, endpoint):
    if not endpoint:
        raise LazySenseError("missing argument: endpoint")
    return request(config, "GET", endpoint)


def post_raw(config, endpoint, data=None):
    if not endpoint:
        raise LazySenseError("missing argument: endpoint")
    return request(config, "POST", endpoint, data)


def get_json(config, endpoint):
    raw = get_raw(config, endpoint)
    return json.loads(raw)


def post_json(config, endpoint, data=None):
    raw = post_raw(config, endpoint, data)
    return json.loads(raw)


def download(config, endpoint, dest_path):
    config.validate()
    url = f"{config.base_url}{endpoint}"
    headers = {"Authorization": _auth_header(config), "Accept": "application/octet-stream"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, context=_ssl_context(config)) as resp:
            data = resp.read()
    except urllib.error.URLError as exc:
        raise LazySenseError(f"download from {url} failed: {exc.reason}") from exc
    dest_path.write_bytes(data)


# ---------- validation ----------

def validate_alias_name(name):
    if not ALIAS_NAME_RE.match(name or ""):
        raise LazySenseError(
            f"invalid alias name '{name}' (use letters, numbers, and underscores; do not start with a number)"
        )


def validate_hostname(name):
    if not HOSTNAME_RE.match(name or ""):
        raise LazySenseError(
            f"invalid hostname '{name}' (use letters, numbers, and hyphens; do not start with a hyphen)"
        )


def is_ipv4(value):
    try:
        ipaddress.IPv4Address(value or "")
        return True
    except ValueError:
        return False


def is_mac(value):
    return bool(MAC_RE.match(value or ""))


# ---------- index cache ----------

def write_index_cache(path, mapping):
    path.write_text(json.dumps(mapping), encoding="utf-8")


def read_index_cache(path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def lookup_index_value(path, key, field=None):
    cache = read_index_cache(path)
    if cache is None:
        return None
    entry = cache.get(str(key))
    if entry is None:
        return None
    if isinstance(entry, dict) and field:
        return entry.get(field, "") or ""
    return entry


# ---------- payload builders ----------

def payload_alias_address(ip):
    return {"address": ip}


def payload_rule_enabled(enabled):
    return {"rule": {"enabled": "1" if enabled else "0"}}


def payload_dnsmasq_host(host, domain, ip, hwaddr, descr):
    return {
        "host": {
            "enabled": "1",
            "host": host,
            "domain": domain,
            "local": "1",
            "ip": ip,
            "hwaddr": hwaddr or "",
            "descr": descr,
        }
    }


def payload_firewall_host_alias(name, ip, descr):
    return {
        "alias": {
            "enabled": "1",
            "name": name,
            "type": "host",
            "content": ip,
            "description": descr,
        }
    }


# ---------- reconfigure helpers ----------

def apply_filter_changes(config):
    return post_json(config, "/api/firewall/filter/apply", {})


def reconfigure_dnsmasq(config):
    return post_json(config, "/api/dnsmasq/service/reconfigure", {})


def reconfigure_aliases(config):
    return post_json(config, "/api/firewall/alias/reconfigure", {})


# ---------- host / lease resolution ----------

def find_host_by_selector(rows, selector):
    selector = (selector or "").lower()
    for row in rows:
        ip = row.get("address") or row.get("ip") or ""
        mac = (row.get("hwaddr") or "").lower()
        host = (row.get("hostname") or row.get("host") or "").lower()
        if selector in {ip.lower(), mac, host}:
            try:
                return str(ipaddress.ip_address(ip))
            except ValueError:
                return None
    return None


def resolve_host_ip(config, selector):
    if not selector:
        raise LazySenseError("missing argument: host selector")

    if is_ipv4(selector):
        return str(ipaddress.ip_address(selector))

    if selector.isdigit():
        ip = lookup_index_value(LEASE_INDEX_FILE, selector, "ip")
        if not ip:
            raise LazySenseError(f"no lease at index {selector} (run 'dhcp-leases' first)")
        return ip

    leases = get_json(config, "/api/dnsmasq/leases/search")
    ip = find_host_by_selector(leases.get("rows", []), selector)
    if ip:
        return ip

    hosts = get_json(config, "/api/dnsmasq/settings/searchHost")
    ip = find_host_by_selector(hosts.get("rows", []), selector)
    if ip:
        return ip

    if is_mac(selector):
        raise LazySenseError(f"no DHCP lease or reservation found for MAC {selector}")
    raise LazySenseError(f"no DHCP lease or reservation found for host '{selector}'")


def find_alias_uuid(config, name):
    data = get_json(config, "/api/firewall/alias/searchItem")
    for row in data.get("rows", []):
        if row.get("name") == name:
            return row.get("uuid", "")
    return None


def find_dnsmasq_host_uuid(config, ip, hwaddr):
    data = get_json(config, "/api/dnsmasq/settings/searchHost")
    target_mac = (hwaddr or "").lower()
    for row in data.get("rows", []):
        row_ip = row.get("ip") or ""
        row_mac = (row.get("hwaddr") or "").lower()
        if row_ip == ip or (target_mac and row_mac == target_mac):
            return row.get("uuid", "")
    return None


def find_lease_by_ip(config, ip):
    data = get_json(config, "/api/dnsmasq/leases/search")
    for row in data.get("rows", []):
        if row.get("address") == ip:
            return {
                "ip": row.get("address", ""),
                "hwaddr": row.get("hwaddr", "") or "",
                "hostname": row.get("hostname", "") or "",
            }
    return None


def resolve_lease(key):
    if not key:
        raise LazySenseError("missing argument: lease index or ip")

    if is_ipv4(key):
        return {"ip": key, "hwaddr": "", "hostname": ""}

    ip = lookup_index_value(LEASE_INDEX_FILE, key, "ip")
    if not ip:
        raise LazySenseError(f"no lease at index {key} (run 'dhcp-leases' first)")
    hwaddr = lookup_index_value(LEASE_INDEX_FILE, key, "hwaddr") or ""
    hostname = lookup_index_value(LEASE_INDEX_FILE, key, "hostname") or ""
    return {"ip": ip, "hwaddr": hwaddr, "hostname": hostname}


def get_dhcp_domain(config):
    if config.domain:
        return config.domain

    def walk(value):
        if isinstance(value, dict):
            item = value.get("domain")
            if isinstance(item, str) and item.strip():
                return item.strip()
            for key, item in value.items():
                if key.startswith("%"):
                    continue
                found = walk(item)
                if found:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = walk(item)
                if found:
                    return found
        return None

    data = get_json(config, "/api/dnsmasq/settings/get")
    domain = walk(data)
    if not domain:
        raise LazySenseError(
            "cannot read DHCP/domain setting from OPNsense; set OPNSENSE_DOMAIN explicitly if needed"
        )
    return domain


# ---------- high level commands ----------

def list_rules(config, iface_filter="", dir_filter=""):
    data = get_json(config, "/api/firewall/filter/searchRule")
    rows = sorted(data.get("rows", []), key=lambda r: float(r.get("sort_order") or 0))

    ifaces = {v.strip().lower() for v in iface_filter.split(",") if v.strip()}
    dirs = {v.strip().lower() for v in dir_filter.split(",") if v.strip()}

    def row_ifaces(row):
        raw = row.get("%interface") or row.get("interface") or ""
        return {v.strip().lower() for v in raw.split(",") if v.strip()}

    def matches(row):
        if ifaces and not (row_ifaces(row) & ifaces):
            return False
        if dirs and (row.get("%direction") or "").strip().lower() not in dirs:
            return False
        return True

    return [row for row in rows if matches(row)]


def toggle_rule(config, uuid, enabled):
    payload = payload_rule_enabled(enabled)
    post_json(config, f"/api/firewall/filter/setRule/{uuid}", payload)
    apply_filter_changes(config)


def list_aliases(config):
    data = get_json(config, "/api/firewall/alias/searchItem")
    return data.get("rows", [])


def host_alias(config, name, selector, description="host alias set via lazysense"):
    validate_alias_name(name)
    ip = resolve_host_ip(config, selector)
    payload = payload_firewall_host_alias(name, ip, description)
    uuid = find_alias_uuid(config, name)
    if uuid:
        post_json(config, f"/api/firewall/alias/setItem/{uuid}", payload)
    else:
        post_json(config, "/api/firewall/alias/addItem", payload)
    reconfigure_aliases(config)
    return ip


def alias_add_ip(config, name, ip):
    validate_alias_name(name)
    payload = payload_alias_address(ip)
    return post_json(config, f"/api/firewall/alias_util/add/{name}", payload)


def alias_remove_ip(config, name, ip):
    validate_alias_name(name)
    payload = payload_alias_address(ip)
    return post_json(config, f"/api/firewall/alias_util/delete/{name}", payload)


def list_dhcp_leases(config):
    data = get_json(config, "/api/dnsmasq/leases/search")
    return data.get("rows", [])


def dhcp_set_alias(config, key, alias_name):
    validate_hostname(alias_name)
    lease = resolve_lease(key)
    ip, hwaddr = lease["ip"], lease["hwaddr"]
    domain = get_dhcp_domain(config)
    payload = payload_dnsmasq_host(alias_name, domain, ip, hwaddr, f"API: {alias_name}")
    uuid = find_dnsmasq_host_uuid(config, ip, hwaddr)
    if uuid:
        post_json(config, f"/api/dnsmasq/settings/setHost/{uuid}", payload)
    else:
        post_json(config, "/api/dnsmasq/settings/addHost", payload)
    reconfigure_dnsmasq(config)
    return {"ip": ip, "domain": domain}


def dhcp_set_reservation(config, key):
    lease = resolve_lease(key)
    ip, hwaddr, hostname = lease["ip"], lease["hwaddr"], lease["hostname"]
    if not hwaddr:
        raise LazySenseError(f"lease '{key}' has no MAC address; cannot create reservation")
    if not hostname or hostname == "*":
        hostname = f"lease-{ip.replace('.', '-')}"
    domain = get_dhcp_domain(config)
    payload = payload_dnsmasq_host(hostname, domain, ip, hwaddr, "reservation set via lazysense")
    post_json(config, "/api/dnsmasq/settings/addHost", payload)
    reconfigure_dnsmasq(config)
    return {"ip": ip, "hostname": hostname, "domain": domain}


def list_reservations(config):
    data = get_json(config, "/api/dnsmasq/settings/searchHost")
    return data.get("rows", [])


def reservation_delete(config, uuid):
    post_json(config, f"/api/dnsmasq/settings/delHost/{uuid}", {})
    reconfigure_dnsmasq(config)


def backup_list(config):
    data = get_json(config, "/api/core/backup/backups/this")
    return data.get("items", [])


def backup_download(config, output_dir, backup_id=None):
    import datetime
    import xml.etree.ElementTree as ET

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = output_dir / f"opnsense-config-{timestamp}.xml"
    tmp_file = output_file.with_suffix(output_file.suffix + ".tmp")

    endpoint = "/api/core/backup/download/this"
    if backup_id:
        endpoint = f"{endpoint}/{backup_id}"

    download(config, endpoint, tmp_file)

    try:
        root = ET.parse(tmp_file).getroot()
        valid = root.tag == "opnsense"
    except ET.ParseError:
        valid = False

    if not valid:
        tmp_file.unlink(missing_ok=True)
        raise LazySenseError("downloaded data does not look like an OPNsense config XML")

    tmp_file.rename(output_file)
    output_file.chmod(0o600)
    return output_file
