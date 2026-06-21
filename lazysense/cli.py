"""Non-interactive CLI dispatch, mirrors the original lazysense.sh argument grammar."""

import sys

from . import api, render

HELP_TEXT = """OPNsense API Helper

Usage: lazysense.py [options] <command> [args]

Options:
    --insecure, -k                  Disable SSL certificate validation
    --secure                        Enable SSL certificate validation
    --json                          Print raw JSON instead of a formatted table

System:
    status                          System status
    firmware-status                 Firmware status
    interfaces                      Interface configuration
    version                          Show OPNsense version
    reboot                          Reboot system

Firewall:
    rules [if] [dir]                Show firewall rules, optionally filtered
                                     by interface(s) and/or direction(s)
    rule-enable <n>                 Enable rule by index (from rules)
    rule-disable <n>                Disable rule by index (from rules)
    firewall-stats                  Firewall pf statistics
    suricata-status                 Suricata IDS/IPS status

Aliases:
    aliases                         Show firewall aliases
    host-alias <name> <host> [desc] Create/update a firewall host alias from IP, DHCP index, MAC, or hostname
    alias-add-ip <name> <ip>        Add an IP to a manual alias
    alias-remove-ip <name> <ip>     Remove an IP from a manual alias

DHCP / DNS:
    dhcp-leases                     Show DHCP leases (indexed)
    dhcp-set-alias <n|ip> <name>    Set hostname/alias for a lease
    dhcp-host-alias <n|ip> <name>   Alias for dhcp-set-alias
    dhcp-set-reservation <n|ip>     Turn a dynamic lease into a static reservation
    reservations                    Show static DHCP reservations
    reservation-delete <n>          Delete a static reservation by index (from reservations)
    unbound-stats                   Unbound DNS statistics

Raw:
    get <endpoint>                  Raw GET request to endpoint
    post <endpoint> [data]          Raw POST request with JSON data

Backup:
    backup [dir] [backup_id]        Download latest/current config backup to dir
    backup-list                     Show available local config backups on OPNsense

    help                            Show this help

Environment Variables:
    OPNSENSE_HOST, OPNSENSE_PORT, OPNSENSE_KEY, OPNSENSE_SECRET, OPNSENSE_INSECURE, OPNSENSE_DOMAIN

Credentials File (~/.opnsense/credentials):
    OPNSENSE_HOST=...
    OPNSENSE_PORT=443
    OPNSENSE_KEY=...
    OPNSENSE_SECRET=...
    OPNSENSE_INSECURE=true
    OPNSENSE_DOMAIN=...     # optional override; normally read from OPNsense DHCP/DNS settings
"""


def die(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def need_arg(value, name):
    if not value:
        die(f"missing argument: {name}")


def is_help_arg(value):
    return value in ("help", "--help", "-h")


def parse_global_flags(argv):
    config = api.Config()
    json_mode = False
    rest = []
    for arg in argv:
        if arg in ("--insecure", "-k"):
            config.insecure = True
        elif arg == "--secure":
            config.insecure = False
        elif arg == "--json":
            json_mode = True
        else:
            rest.append(arg)
    return config, json_mode, rest


def run_get(config, json_mode, endpoint):
    need_arg(endpoint, "endpoint")
    raw = api.get_raw(config, endpoint)
    if json_mode:
        render.pretty_json_or_raw(raw)
    else:
        import json as jsonlib
        try:
            data = jsonlib.loads(raw)
        except jsonlib.JSONDecodeError:
            print("(non-JSON response, use --json to see raw output)")
            return
        render.render_kv_table(data)


def run_post(config, endpoint, data):
    need_arg(endpoint, "endpoint")
    payload = None
    if data:
        import json as jsonlib
        payload = jsonlib.loads(data)
    raw = api.post_raw(config, endpoint, payload)
    render.pretty_json_or_raw(raw)


def cmd_rules(config, json_mode, args):
    if args and is_help_arg(args[0]):
        print_rules_help()
        return
    interfaces = args[0] if len(args) > 0 else ""
    directions = args[1] if len(args) > 1 else ""
    if json_mode:
        run_get(config, True, "/api/firewall/filter/searchRule")
        return
    rows = api.list_rules(config, interfaces, directions)
    render.render_rules_table(rows)


def print_rules_help():
    print("""Usage: lazysense.py rules [interface[,interface...]] [direction[,direction...]]

Show firewall rules, optionally filtered by interface and/or direction.
Filters are case-insensitive and comma-separated for multiple values.

Arguments:
    interface       LAN, WAN, WireGuardVPN, etc. (omit or "" for all)
    direction       in, out (omit or "" for all)

Examples:
    lazysense.py rules
    lazysense.py rules LAN
    lazysense.py rules LAN in
    lazysense.py rules LAN,WAN in,out
    lazysense.py rules "" out
""")


def cmd_rule_toggle(config, idx, enabled):
    need_arg(idx, "rule index")
    uuid = api.lookup_index_value(api.RULE_INDEX_FILE, idx)
    if not uuid:
        die(f"no rule at index {idx} (run 'rules' first)")
    api.toggle_rule(config, uuid, enabled)
    print(f"Rule {idx} {'enabled' if enabled else 'disabled'}.")


def cmd_aliases(config, json_mode):
    if json_mode:
        run_get(config, True, "/api/firewall/alias/searchItem")
        return
    render.render_aliases_table(api.list_aliases(config))


def cmd_host_alias(config, args):
    if args and is_help_arg(args[0]):
        print("""Usage: lazysense.py host-alias <alias_name> <host> [description]

Create or update a firewall alias of type "host".

Arguments:
    alias_name      OPNsense firewall alias name. Use letters, numbers, underscores.
    host            IP address, DHCP lease index, MAC address, or hostname.
    description     Optional alias description.

Examples:
    lazysense.py dhcp-leases
    lazysense.py host-alias PRINTER_LAN 192.168.88.50
    lazysense.py host-alias PRINTER_LAN 12
    lazysense.py host-alias PRINTER_LAN aa:bb:cc:dd:ee:ff
    lazysense.py host-alias PRINTER_LAN printer
""")
        return
    name = args[0] if len(args) > 0 else ""
    selector = args[1] if len(args) > 1 else ""
    description = args[2] if len(args) > 2 else "host alias set via lazysense.py"
    need_arg(name, "alias name")
    need_arg(selector, "host selector")
    ip = api.host_alias(config, name, selector, description)
    print(f"Saved firewall alias {name} -> {ip}. UI: Firewall > Aliases")


def cmd_dhcp_set_alias(config, args):
    if args and is_help_arg(args[0]):
        print("""Usage: lazysense.py dhcp-set-alias <lease_index|ip> <hostname>

Create or update a DNS/DHCP host entry for a LAN device.

Arguments:
    lease_index     Index shown by "dhcp-leases".
    ip              Device IP address from the DHCP lease list.
    hostname        DNS hostname to assign. Use letters, numbers, hyphens.

Examples:
    lazysense.py dhcp-leases
    lazysense.py dhcp-set-alias 12 printer
    lazysense.py dhcp-set-alias 192.168.88.50 printer

Notes:
    For index-based use, run "dhcp-leases" first so the script can build its index.
    If a DNS/DHCP reservation already exists for the same IP/MAC, it is updated.
    Domain is read from OPNsense DHCP/DNS settings. OPNSENSE_DOMAIN can override it.
    The host is marked Local.
""")
        return
    key = args[0] if len(args) > 0 else ""
    alias_name = args[1] if len(args) > 1 else ""
    need_arg(key, "lease index or ip")
    need_arg(alias_name, "hostname")
    result = api.dhcp_set_alias(config, key, alias_name)
    print(
        f"Saved local DNS/DHCP host alias {alias_name}.{result['domain']} -> {result['ip']}. "
        "UI: Services > Dnsmasq DNS & DHCP > Hosts"
    )


def cmd_dhcp_set_reservation(config, args):
    if args and is_help_arg(args[0]):
        print("""Usage: lazysense.py dhcp-set-reservation <lease_index|ip>

Turn a dynamic DHCP lease into a static DNS/DHCP host reservation.

Examples:
    lazysense.py dhcp-leases
    lazysense.py dhcp-set-reservation 12
    lazysense.py dhcp-set-reservation 192.168.88.50
""")
        return
    key = args[0] if len(args) > 0 else ""
    result = api.dhcp_set_reservation(config, key)
    print(f"Saved static reservation {result['hostname']}.{result['domain']} -> {result['ip']}.")


def cmd_reservation_delete(config, idx):
    need_arg(idx, "reservation index")
    uuid = api.lookup_index_value(api.RESERVATION_INDEX_FILE, idx)
    if not uuid:
        die(f"no reservation at index {idx} (run 'reservations' first)")
    api.reservation_delete(config, uuid)
    print(f"Reservation {idx} deleted.")


def cmd_backup(config, args):
    output_dir = args[0] if len(args) > 0 else "backups"
    backup_id = args[1] if len(args) > 1 else None
    if is_help_arg(output_dir):
        print("""Usage: lazysense.py backup [directory] [backup_id]

Download an OPNsense configuration backup and save it locally.

Arguments:
    directory       Optional output directory. Default: ./backups
    backup_id       Optional backup id from "backup-list". Default: latest backup.

Examples:
    lazysense.py backup
    lazysense.py backup ./backups
    lazysense.py backup ./backups config-1750433700.xml

Notes:
    The saved config can contain secrets. The script sets file permissions to 600.
    Run "backup-list" to see backup ids available from OPNsense.
""")
        return
    path = api.backup_download(config, output_dir, backup_id)
    print(f"Saved backup: {path}")


def cmd_backup_list(config, json_mode):
    if json_mode:
        run_get(config, True, "/api/core/backup/backups/this")
        return
    render.render_backup_list_table(api.backup_list(config))


def main(argv):
    config, json_mode, args = parse_global_flags(argv)

    if not args:
        cmd = "help"
        rest = []
    else:
        cmd = args[0]
        rest = args[1:]

    try:
        if cmd == "get":
            run_get(config, json_mode, rest[0] if rest else "")
        elif cmd == "post":
            run_post(config, rest[0] if rest else "", rest[1] if len(rest) > 1 else "")
        elif cmd == "status":
            run_get(config, json_mode, "/api/core/system/status")
        elif cmd == "firmware-status":
            run_get(config, json_mode, "/api/core/firmware/status")
        elif cmd == "interfaces":
            run_get(config, json_mode, "/api/diagnostics/interface/getInterfaceConfig")
        elif cmd == "firewall-stats":
            run_get(config, json_mode, "/api/diagnostics/firewall/pfstatists")
        elif cmd == "suricata-status":
            run_get(config, json_mode, "/api/ids/service/status")
        elif cmd == "unbound-stats":
            run_get(config, json_mode, "/api/unbound/diagnostics/stats")
        elif cmd == "backup":
            cmd_backup(config, rest)
        elif cmd == "backup-list":
            if rest and is_help_arg(rest[0]):
                cmd_backup(config, ["help"])
            else:
                cmd_backup_list(config, json_mode)
        elif cmd == "rules":
            cmd_rules(config, json_mode, rest)
        elif cmd == "rule-enable":
            cmd_rule_toggle(config, rest[0] if rest else "", True)
        elif cmd == "rule-disable":
            cmd_rule_toggle(config, rest[0] if rest else "", False)
        elif cmd == "aliases":
            cmd_aliases(config, json_mode)
        elif cmd in ("host-alias", "alias-host"):
            cmd_host_alias(config, rest)
        elif cmd == "alias-add-ip":
            name = rest[0] if len(rest) > 0 else ""
            ip = rest[1] if len(rest) > 1 else ""
            need_arg(name, "alias name")
            need_arg(ip, "ip")
            api.alias_add_ip(config, name, ip)
        elif cmd == "alias-remove-ip":
            name = rest[0] if len(rest) > 0 else ""
            ip = rest[1] if len(rest) > 1 else ""
            need_arg(name, "alias name")
            need_arg(ip, "ip")
            api.alias_remove_ip(config, name, ip)
        elif cmd == "dhcp-leases":
            if json_mode:
                run_get(config, True, "/api/dnsmasq/leases/search")
            else:
                render.render_leases_table(api.list_dhcp_leases(config))
        elif cmd in ("dhcp-set-alias", "dhcp-host-alias"):
            cmd_dhcp_set_alias(config, rest)
        elif cmd == "dhcp-set-reservation":
            cmd_dhcp_set_reservation(config, rest)
        elif cmd == "reservations":
            if json_mode:
                run_get(config, True, "/api/dnsmasq/settings/searchHost")
            else:
                render.render_reservations_table(api.list_reservations(config))
        elif cmd == "reservation-delete":
            cmd_reservation_delete(config, rest[0] if rest else "")
        elif cmd == "reboot":
            print("Rebooting OPNsense...")
            api.post_json(config, "/api/core/system/reboot", {})
        elif cmd == "version":
            data = api.get_json(config, "/api/core/firmware/status")
            version = data.get("product_version") or data.get("product", {}).get("product_version") or "Version unknown"
            print(version)
        elif cmd in ("help", "--help", "-h"):
            print(HELP_TEXT)
        else:
            print(f"Unknown command: {cmd}", file=sys.stderr)
            print(HELP_TEXT, file=sys.stderr)
            sys.exit(1)
    except api.LazySenseError as exc:
        die(str(exc))
