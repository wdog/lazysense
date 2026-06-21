"""ANSI table/kv rendering for non-interactive CLI output."""

import datetime
import ipaddress
import json

from . import api

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def trunc(value, width):
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[: width - 3] + "..."


def flatten(obj, prefix=""):
    items = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            items.extend(flatten(value, name))
    elif isinstance(obj, list):
        if all(isinstance(item, (str, int, float, bool)) or item is None for item in obj):
            items.append((prefix, ", ".join("" if item is None else str(item) for item in obj)))
        else:
            for index, value in enumerate(obj):
                items.extend(flatten(value, f"{prefix}[{index}]"))
    else:
        items.append((prefix, obj))
    return items


def render_kv_table(data):
    rows = flatten(data)
    if not rows:
        print("(empty response)")
        return

    key_width = min(max((len(key) for key, _ in rows), default=10), 50)
    print(f"{BOLD}{'KEY'.ljust(key_width)}  VALUE{RESET}")
    print(GRAY + "-" * (key_width + 40) + RESET)
    for key, value in rows:
        print(f"{CYAN}{key.ljust(key_width)}{RESET}  {'' if value is None else value}")


def pretty_json_or_raw(raw_bytes):
    try:
        parsed = json.loads(raw_bytes)
    except json.JSONDecodeError:
        print(raw_bytes.decode(errors="replace"), end="")
    else:
        print(json.dumps(parsed, indent=4, sort_keys=True))


def color_action(action):
    action = action or "-"
    if action == "Pass":
        return f"{GREEN}{action:5}{RESET}"
    if action == "Block":
        return f"{RED}{action:5}{RESET}"
    if action == "Reject":
        return f"{YELLOW}{action:6}{RESET}"
    return f"{GRAY}{action:5}{RESET}"


def render_rules_table(rows):
    columns = ["#", "ST", "ACTION", "DIR", "IF", "SOURCE", "DEST", "DESCRIPTION"]
    widths = [4, 3, 7, 4, 6, 20, 20, 38]
    header = "  ".join(col.ljust(w) for col, w in zip(columns, widths))
    print(f"{BOLD}{header}{RESET}")
    print(GRAY + "-" * (sum(widths) + 2 * (len(widths) - 1)) + RESET)

    index = {}
    for pos, row in enumerate(rows):
        index[str(pos)] = row.get("uuid", "")
        enabled = row.get("enabled") == "1"
        state = f"{GREEN}ON {RESET}" if enabled else f"{GRAY}OFF{RESET}"
        action = color_action(row.get("%action"))
        direction = trunc(row.get("%direction"), widths[3]).ljust(widths[3])
        interface = trunc(row.get("%interface") or row.get("interface") or "-", widths[4]).ljust(widths[4])
        source = trunc(row.get("source_net") or "any", widths[5]).ljust(widths[5])
        dest = trunc(row.get("destination_net") or "any", widths[6]).ljust(widths[6])
        desc = trunc(row.get("description"), widths[7])
        print(
            f"{GRAY}{str(pos).ljust(widths[0])}{RESET}  {state}  {action}  "
            f"{direction}  {interface}  {CYAN}{source}{RESET}  {CYAN}{dest}{RESET}  {desc}"
        )

    api.write_index_cache(api.RULE_INDEX_FILE, index)
    print()
    print(f"{GRAY}{len(rows)} rule(s). Use rule-enable/rule-disable <#> to toggle.{RESET}")


def render_aliases_table(rows):
    columns = ["NAME", "TYPE", "ITEMS", "IN BLOCK", "OUT BLOCK", "UPDATED", "DESCRIPTION"]
    widths = [16, 14, 8, 9, 9, 20, 28]
    header = "  ".join(col.ljust(w) for col, w in zip(columns, widths))
    print(f"{BOLD}{header}{RESET}")
    print(GRAY + "-" * (sum(widths) + 2 * (len(widths) - 1)) + RESET)

    for row in rows:
        name = trunc(row.get("name"), widths[0]).ljust(widths[0])
        alias_type = trunc(row.get("%type"), widths[1]).ljust(widths[1])
        items = str(row.get("current_items") or 0).ljust(widths[2])
        in_block = str(row.get("in_block_p") or 0).ljust(widths[3])
        out_block = str(row.get("out_block_p") or 0).ljust(widths[4])
        updated = trunc(row.get("last_updated") or "-", widths[5]).ljust(widths[5])
        desc = trunc(row.get("description"), widths[6])
        print(f"{CYAN}{name}{RESET}  {alias_type}  {items}  {in_block}  {out_block}  {updated}  {desc}")


def _expires(value):
    if not value:
        return "static"
    try:
        return datetime.datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M")
    except (OSError, ValueError):
        return str(value)


def _ip_sort_key(row):
    try:
        return int(ipaddress.ip_address(row.get("address") or "0.0.0.0"))
    except ValueError:
        return 0


def render_leases_table(rows):
    rows = sorted(rows, key=_ip_sort_key)
    columns = ["#", "IP ADDRESS", "HOSTNAME", "MAC", "VENDOR", "EXPIRES", "RES"]
    widths = [4, 15, 18, 17, 22, 17, 3]
    header = "  ".join(col.ljust(w) for col, w in zip(columns, widths))
    print(f"{BOLD}{header}{RESET}")
    print(GRAY + "-" * (sum(widths) + 2 * (len(widths) - 1)) + RESET)

    index = {}
    for pos, row in enumerate(rows):
        index[str(pos)] = {
            "ip": row.get("address", ""),
            "hwaddr": row.get("hwaddr", ""),
            "hostname": row.get("hostname", ""),
        }
        ip = (row.get("address") or "").ljust(widths[1])
        host = trunc(row.get("hostname") or "*", widths[2]).ljust(widths[2])
        mac = (row.get("hwaddr") or "").ljust(widths[3])
        vendor = trunc(row.get("mac_info"), widths[4]).ljust(widths[4])
        expiry = _expires(row.get("expire")).ljust(widths[5])
        reserved = f"{GREEN}YES{RESET}" if row.get("is_reserved") else f"{GRAY}no {RESET}"
        print(
            f"{GRAY}{str(pos).ljust(widths[0])}{RESET}  {CYAN}{ip}{RESET}  "
            f"{host}  {mac}  {vendor}  {expiry}  {reserved}"
        )

    api.write_index_cache(api.LEASE_INDEX_FILE, index)
    print()
    print(f"{GRAY}{len(rows)} lease(s). Use dhcp-set-alias/dhcp-set-reservation <#|ip>.{RESET}")


def render_reservations_table(rows):
    columns = ["#", "HOST", "IP", "MAC", "DESCRIPTION"]
    widths = [4, 18, 15, 17, 30]
    header = "  ".join(col.ljust(w) for col, w in zip(columns, widths))
    print(f"{BOLD}{header}{RESET}")
    print(GRAY + "-" * (sum(widths) + 2 * (len(widths) - 1)) + RESET)

    index = {}
    for pos, row in enumerate(rows):
        index[str(pos)] = row.get("uuid", "")
        host = trunc(row.get("host"), widths[1]).ljust(widths[1])
        ip = (row.get("ip") or "").ljust(widths[2])
        mac = (row.get("hwaddr") or "").ljust(widths[3])
        desc = trunc(row.get("descr"), widths[4])
        print(f"{GRAY}{str(pos).ljust(widths[0])}{RESET}  {CYAN}{host}{RESET}  {ip}  {mac}  {desc}")

    api.write_index_cache(api.RESERVATION_INDEX_FILE, index)
    print()
    print(f"{GRAY}{len(rows)} reservation(s). Use reservation-delete <#>.{RESET}")


def render_backup_list_table(rows):
    columns = ["#", "ID", "TIME", "USER", "SIZE", "DESCRIPTION"]
    widths = [4, 28, 25, 14, 10, 34]
    header = "  ".join(col.ljust(w) for col, w in zip(columns, widths))
    print(f"{BOLD}{header}{RESET}")
    print(GRAY + "-" * (sum(widths) + 2 * (len(widths) - 1)) + RESET)

    for pos, row in enumerate(rows):
        backup_id = trunc(row.get("id"), widths[1]).ljust(widths[1])
        timestamp = trunc(row.get("time_iso") or row.get("time"), widths[2]).ljust(widths[2])
        username = trunc(row.get("username"), widths[3]).ljust(widths[3])
        filesize = str(row.get("filesize") or "").ljust(widths[4])
        description = trunc(row.get("description"), widths[5])
        print(
            f"{GRAY}{str(pos).ljust(widths[0])}{RESET}  {CYAN}{backup_id}{RESET}  "
            f"{timestamp}  {username}  {filesize}  {description}"
        )

    print()
    print(f"{GRAY}{len(rows)} backup(s). Use backup [dir] <ID> to download a specific one.{RESET}")
