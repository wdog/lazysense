"""Textual TUI for lazysense. Imported only when running with no CLI arguments."""

import datetime
import ipaddress

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    RichLog,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from . import api

CSS = """
Screen {
    background: $surface;
}
.title {
    text-style: bold;
    color: $accent;
    padding: 1 2;
}
.muted {
    color: $text-muted;
}
DataTable {
    height: 1fr;
}
#filters {
    height: auto;
    padding: 0 1;
}
#filters Input, #filters Select {
    width: 24;
    margin-right: 1;
}
ConfirmModal {
    align: center middle;
}
#confirm-box {
    width: 60;
    height: auto;
    border: thick $accent;
    background: $panel;
    padding: 1 2;
}
InputModal {
    align: center middle;
}
#input-box {
    width: 60;
    height: auto;
    border: thick $accent;
    background: $panel;
    padding: 1 2;
}
.error {
    color: $error;
}
"""


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


class ConfirmModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss_no", "Cancel")]

    def __init__(self, message, on_confirm):
        super().__init__()
        self.message = message
        self.on_confirm = on_confirm

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Label(self.message)
            with Horizontal():
                yield Button("Yes", id="yes", variant="error")
                yield Button("No", id="no", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "yes":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_dismiss_no(self) -> None:
        self.dismiss(False)


class InputModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss_cancel", "Cancel")]

    def __init__(self, title, fields, validators=None):
        super().__init__()
        self.title_text = title
        self.fields = fields
        self.validators = validators or {}

    def compose(self) -> ComposeResult:
        with Vertical(id="input-box"):
            yield Label(self.title_text)
            for field_id, placeholder in self.fields:
                yield Input(placeholder=placeholder, id=field_id)
            yield Label("", id="input-error", classes="error")
            with Horizontal():
                yield Button("Submit", id="submit", variant="success")
                yield Button("Cancel", id="cancel", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        values = {}
        for field_id, _ in self.fields:
            values[field_id] = self.query_one(f"#{field_id}", Input).value.strip()
        for field_id, validator in self.validators.items():
            try:
                validator(values.get(field_id, ""))
            except api.LazySenseError as exc:
                self.query_one("#input-error", Label).update(str(exc))
                return
        self.dismiss(values)

    def action_dismiss_cancel(self) -> None:
        self.dismiss(None)


class KVScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def __init__(self, title, fetcher):
        super().__init__()
        self.title_text = title
        self.fetcher = fetcher

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(self.title_text, classes="title")
        yield DataTable(id="kv-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("KEY", "VALUE")
        self.refresh_data()

    def refresh_data(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            data = self.fetcher()
        except api.LazySenseError as exc:
            self.app.notify(str(exc), severity="error")
            return
        for key, value in flatten(data):
            table.add_row(key, "" if value is None else str(value))


class RulesScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("e", "enable_rule", "Enable"),
        Binding("d", "disable_rule", "Disable"),
        Binding("r", "refresh_rules", "Refresh"),
    ]

    def __init__(self):
        super().__init__()
        self.all_rows = []
        self.index_map = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Firewall Rules", classes="title")
        with Horizontal(id="filters"):
            yield Input(placeholder="interface filter (e.g. LAN,WAN)", id="iface-filter")
            yield Select(
                [("all", "all"), ("in", "in"), ("out", "out")],
                value="all",
                id="dir-filter",
            )
        yield DataTable(id="rules-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "ST", "ACTION", "DIR", "IF", "SOURCE", "DEST", "DESCRIPTION")
        self.action_refresh_rules()
        table.focus()

    def action_refresh_rules(self) -> None:
        try:
            data = api.get_json(self.app.config, "/api/firewall/filter/searchRule")
        except api.LazySenseError as exc:
            self.app.notify(str(exc), severity="error")
            return
        self.all_rows = sorted(data.get("rows", []), key=lambda r: float(r.get("sort_order") or 0))
        self.apply_filter()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "iface-filter":
            self.apply_filter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "dir-filter":
            self.apply_filter()

    def apply_filter(self) -> None:
        iface_text = self.query_one("#iface-filter", Input).value
        dir_value = self.query_one("#dir-filter", Select).value

        ifaces = {v.strip().lower() for v in iface_text.split(",") if v.strip()}
        dirs = {dir_value} if dir_value and dir_value != "all" else set()

        def row_ifaces(row):
            raw = row.get("%interface") or row.get("interface") or ""
            return {v.strip().lower() for v in raw.split(",") if v.strip()}

        def matches(row):
            if ifaces and not (row_ifaces(row) & ifaces):
                return False
            if dirs and (row.get("%direction") or "").strip().lower() not in dirs:
                return False
            return True

        rows = [row for row in self.all_rows if matches(row)]
        table = self.query_one(DataTable)
        table.clear()
        self.index_map = {}
        for pos, row in enumerate(rows):
            self.index_map[pos] = row.get("uuid", "")
            enabled = row.get("enabled") == "1"
            state = "[green]ON[/]" if enabled else "[grey62]OFF[/]"
            action = row.get("%action") or "-"
            color = {"Pass": "green", "Block": "red", "Reject": "yellow"}.get(action, "grey62")
            table.add_row(
                str(pos),
                state,
                f"[{color}]{action}[/]",
                row.get("%direction") or "-",
                row.get("%interface") or row.get("interface") or "-",
                row.get("source_net") or "any",
                row.get("destination_net") or "any",
                row.get("description") or "",
            )

    def _selected_uuid(self):
        table = self.query_one(DataTable)
        if table.cursor_row is None:
            return None
        return self.index_map.get(table.cursor_row)

    def action_enable_rule(self) -> None:
        self._toggle(True)

    def action_disable_rule(self) -> None:
        self._toggle(False)

    def _toggle(self, enabled) -> None:
        uuid = self._selected_uuid()
        if not uuid:
            return

        def do_toggle(confirmed):
            if not confirmed:
                return
            try:
                api.toggle_rule(self.app.config, uuid, enabled)
            except api.LazySenseError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify(f"Rule {'enabled' if enabled else 'disabled'}.")
            self.action_refresh_rules()

        verb = "enable" if enabled else "disable"
        self.app.push_screen(ConfirmModal(f"{verb.capitalize()} this rule?", None), do_toggle)


class LeasesScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("a", "set_alias", "Set alias"),
        Binding("r", "set_reservation", "Reservation"),
        Binding("f5", "refresh_leases", "Refresh"),
    ]

    def __init__(self):
        super().__init__()
        self.lease_index = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("DHCP Leases", classes="title")
        yield DataTable(id="leases-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "IP", "HOSTNAME", "MAC", "VENDOR", "EXPIRES", "RES")
        self.action_refresh_leases()
        table.focus()

    def action_refresh_leases(self) -> None:
        try:
            rows = api.list_dhcp_leases(self.app.config)
        except api.LazySenseError as exc:
            self.app.notify(str(exc), severity="error")
            return

        def ip_key(row):
            try:
                return int(ipaddress.ip_address(row.get("address") or "0.0.0.0"))
            except ValueError:
                return 0

        rows = sorted(rows, key=ip_key)
        table = self.query_one(DataTable)
        table.clear()
        self.lease_index = {}
        for pos, row in enumerate(rows):
            self.lease_index[pos] = {
                "ip": row.get("address", ""),
                "hwaddr": row.get("hwaddr", ""),
                "hostname": row.get("hostname", ""),
            }
            expire = row.get("expire")
            if expire:
                try:
                    expires = datetime.datetime.fromtimestamp(int(expire)).strftime("%Y-%m-%d %H:%M")
                except (OSError, ValueError):
                    expires = str(expire)
            else:
                expires = "static"
            reserved = "[green]YES[/]" if row.get("is_reserved") else "[grey62]no[/]"
            table.add_row(
                str(pos),
                row.get("address") or "",
                row.get("hostname") or "*",
                row.get("hwaddr") or "",
                row.get("mac_info") or "",
                expires,
                reserved,
            )

    def _selected_lease(self):
        table = self.query_one(DataTable)
        if table.cursor_row is None:
            return None
        return self.lease_index.get(table.cursor_row)

    def action_set_alias(self) -> None:
        lease = self._selected_lease()
        if not lease:
            return

        def handle(values):
            if not values:
                return
            try:
                result = api.dhcp_set_alias(self.app.config, lease["ip"], values["hostname"])
            except api.LazySenseError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify(f"Alias saved: {values['hostname']}.{result['domain']} -> {result['ip']}")
            self.action_refresh_leases()

        self.app.push_screen(
            InputModal(
                f"Set hostname for {lease['ip']}",
                [("hostname", "hostname")],
                {"hostname": api.validate_hostname},
            ),
            handle,
        )

    def action_set_reservation(self) -> None:
        lease = self._selected_lease()
        if not lease:
            return

        def do_reserve(confirmed):
            if not confirmed:
                return
            try:
                result = api.dhcp_set_reservation(self.app.config, lease["ip"])
            except api.LazySenseError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify(f"Reservation saved: {result['hostname']} -> {result['ip']}")
            self.action_refresh_leases()

        self.app.push_screen(ConfirmModal(f"Create reservation for {lease['ip']}?", None), do_reserve)


class ReservationsScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("d", "delete_reservation", "Delete"),
        Binding("f5", "refresh_reservations", "Refresh"),
    ]

    def __init__(self):
        super().__init__()
        self.index_map = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("DHCP Reservations", classes="title")
        yield DataTable(id="reservations-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "HOST", "IP", "MAC", "DESCRIPTION")
        self.action_refresh_reservations()
        table.focus()

    def action_refresh_reservations(self) -> None:
        try:
            rows = api.list_reservations(self.app.config)
        except api.LazySenseError as exc:
            self.app.notify(str(exc), severity="error")
            return
        table = self.query_one(DataTable)
        table.clear()
        self.index_map = {}
        for pos, row in enumerate(rows):
            self.index_map[pos] = row.get("uuid", "")
            table.add_row(
                str(pos),
                row.get("host") or "",
                row.get("ip") or "",
                row.get("hwaddr") or "",
                row.get("descr") or "",
            )

    def action_delete_reservation(self) -> None:
        table = self.query_one(DataTable)
        if table.cursor_row is None:
            return
        uuid = self.index_map.get(table.cursor_row)
        if not uuid:
            return

        def do_delete(confirmed):
            if not confirmed:
                return
            try:
                api.reservation_delete(self.app.config, uuid)
            except api.LazySenseError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify("Reservation deleted.")
            self.action_refresh_reservations()

        self.app.push_screen(ConfirmModal("Delete this reservation?", None), do_delete)


class AliasesScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("n", "new_alias", "New/Edit"),
        Binding("f5", "refresh_aliases", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Firewall Aliases", classes="title")
        yield DataTable(id="aliases-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("NAME", "TYPE", "ITEMS", "IN BLOCK", "OUT BLOCK", "UPDATED", "DESCRIPTION")
        self.action_refresh_aliases()

    def action_refresh_aliases(self) -> None:
        try:
            rows = api.list_aliases(self.app.config)
        except api.LazySenseError as exc:
            self.app.notify(str(exc), severity="error")
            return
        table = self.query_one(DataTable)
        table.clear()
        for row in rows:
            table.add_row(
                row.get("name") or "",
                row.get("%type") or "",
                str(row.get("current_items") or 0),
                str(row.get("in_block_p") or 0),
                str(row.get("out_block_p") or 0),
                row.get("last_updated") or "-",
                row.get("description") or "",
            )

    def action_new_alias(self) -> None:
        def handle(values):
            if not values:
                return
            try:
                ip = api.host_alias(
                    self.app.config,
                    values["name"],
                    values["host"],
                    values.get("description") or "host alias set via lazysense",
                )
            except api.LazySenseError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify(f"Alias saved: {values['name']} -> {ip}")
            self.action_refresh_aliases()

        self.app.push_screen(
            InputModal(
                "New/Update host alias",
                [("name", "alias name"), ("host", "ip / lease index / mac / hostname"), ("description", "description (optional)")],
                {"name": api.validate_alias_name},
            ),
            handle,
        )


class BackupScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("d", "download_backup", "Download latest"),
        Binding("f5", "refresh_backups", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Configuration Backups", classes="title")
        yield DataTable(id="backups-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("#", "ID", "TIME", "USER", "SIZE", "DESCRIPTION")
        self.action_refresh_backups()

    def action_refresh_backups(self) -> None:
        try:
            rows = api.backup_list(self.app.config)
        except api.LazySenseError as exc:
            self.app.notify(str(exc), severity="error")
            return
        table = self.query_one(DataTable)
        table.clear()
        for pos, row in enumerate(rows):
            table.add_row(
                str(pos),
                row.get("id") or "",
                row.get("time_iso") or row.get("time") or "",
                row.get("username") or "",
                str(row.get("filesize") or ""),
                row.get("description") or "",
            )

    def action_download_backup(self) -> None:
        def do_download(confirmed):
            if not confirmed:
                return
            try:
                path = api.backup_download(self.app.config, "backups")
            except api.LazySenseError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify(f"Saved backup: {path}")

        self.app.push_screen(ConfirmModal("Download latest backup to ./backups?", None), do_download)


class RawScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Raw API Request", classes="title")
        with Horizontal(id="filters"):
            yield Select([("GET", "GET"), ("POST", "POST")], value="GET", id="raw-method")
            yield Input(placeholder="/api/core/system/status", id="raw-endpoint")
        yield Input(placeholder='POST body JSON (optional)', id="raw-body")
        yield Button("Send", id="raw-send")
        yield RichLog(id="raw-output", wrap=True, highlight=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "raw-send":
            return
        method = self.query_one("#raw-method", Select).value
        endpoint = self.query_one("#raw-endpoint", Input).value.strip()
        body = self.query_one("#raw-body", Input).value.strip()
        log = self.query_one(RichLog)
        log.clear()
        if not endpoint:
            log.write("[red]Error: endpoint required[/]")
            return
        try:
            import json as jsonlib
            if method == "POST":
                payload = jsonlib.loads(body) if body else {}
                data = api.post_json(self.app.config, endpoint, payload)
            else:
                data = api.get_json(self.app.config, endpoint)
            log.write(jsonlib.dumps(data, indent=2, sort_keys=True))
        except Exception as exc:  # noqa: BLE001 - surface any error in the log widget
            log.write(f"[red]Error: {exc}[/]")


MENU_ITEMS = [
    ("status", "System status"),
    ("firmware-status", "Firmware status"),
    ("interfaces", "Interface configuration"),
    ("rules", "Firewall rules"),
    ("firewall-stats", "Firewall pf statistics"),
    ("suricata-status", "Suricata IDS/IPS status"),
    ("aliases", "Firewall aliases"),
    ("dhcp-leases", "DHCP leases"),
    ("reservations", "DHCP reservations"),
    ("unbound-stats", "Unbound DNS statistics"),
    ("backups", "Configuration backups"),
    ("raw", "Raw API request"),
    ("reboot", "Reboot OPNsense"),
    ("quit", "Quit"),
]

MENU_ICONS = {
    "status": "\U0001F4E1",
    "firmware-status": "\U0001F527",
    "interfaces": "\U0001F50C",
    "rules": "\U0001F6E1",
    "firewall-stats": "\U0001F4CA",
    "suricata-status": "\U0001F9E0",
    "aliases": "\U0001F3F7",
    "dhcp-leases": "\U0001F4DD",
    "reservations": "\U0001F4CC",
    "unbound-stats": "\U0001F310",
    "backups": "\U0001F4BE",
    "raw": "\U0001F9EA",
    "reboot": "\U0001F504",
    "quit": "\U0001F6AA",
}


class MainMenuScreen(Screen):
    BINDINGS = [Binding("q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("\U0001F9ED lazysense", classes="title")
        options = [
            Option(f"{MENU_ICONS.get(key, '•')}  {label}", id=key)
            for key, label in MENU_ITEMS
        ]
        yield OptionList(*options, id="main-menu")
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        key = event.option.id
        if key == "quit":
            self.app.exit()
        elif key == "status":
            self.app.push_screen(KVScreen("System Status", lambda: api.get_json(self.app.config, "/api/core/system/status")))
        elif key == "firmware-status":
            self.app.push_screen(KVScreen("Firmware Status", lambda: api.get_json(self.app.config, "/api/core/firmware/status")))
        elif key == "interfaces":
            self.app.push_screen(KVScreen("Interfaces", lambda: api.get_json(self.app.config, "/api/diagnostics/interface/getInterfaceConfig")))
        elif key == "firewall-stats":
            self.app.push_screen(KVScreen("Firewall Stats", lambda: api.get_json(self.app.config, "/api/diagnostics/firewall/pfstatists")))
        elif key == "suricata-status":
            self.app.push_screen(KVScreen("Suricata Status", lambda: api.get_json(self.app.config, "/api/ids/service/status")))
        elif key == "unbound-stats":
            self.app.push_screen(KVScreen("Unbound Stats", lambda: api.get_json(self.app.config, "/api/unbound/diagnostics/stats")))
        elif key == "rules":
            self.app.push_screen(RulesScreen())
        elif key == "aliases":
            self.app.push_screen(AliasesScreen())
        elif key == "dhcp-leases":
            self.app.push_screen(LeasesScreen())
        elif key == "reservations":
            self.app.push_screen(ReservationsScreen())
        elif key == "backups":
            self.app.push_screen(BackupScreen())
        elif key == "raw":
            self.app.push_screen(RawScreen())
        elif key == "reboot":
            def do_reboot(confirmed):
                if not confirmed:
                    return

                def really_reboot(confirmed2):
                    if not confirmed2:
                        return
                    try:
                        api.post_json(self.app.config, "/api/core/system/reboot", {})
                    except api.LazySenseError as exc:
                        self.app.notify(str(exc), severity="error")
                        return
                    self.app.notify("Reboot triggered.")

                self.app.push_screen(ConfirmModal("Really reboot OPNsense now? This cannot be undone.", None), really_reboot)

            self.app.push_screen(ConfirmModal("Reboot OPNsense?", None), do_reboot)


class LazySenseApp(App):
    CSS = CSS
    TITLE = "lazysense"
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self):
        super().__init__()
        self.config = api.Config()

    def on_mount(self) -> None:
        self.push_screen(MainMenuScreen())


def run():
    LazySenseApp().run()
