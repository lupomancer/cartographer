"""Textual UI for Cartographer."""
from __future__ import annotations

import csv
import ipaddress
import sys
import time
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Input, ProgressBar, Static

from . import scan

COLUMNS = [("ip", "IP"), ("hostname", "Hostname"), ("mac", "MAC"), ("vendor", "Manufacturer"),
           ("rtt", "RTT"), ("ports", "Ports")]


def _fmt_ports(h: scan.Host) -> str:
    return ",".join(scan.PORTS[p] for p in h.ports)


class Cartographer(App):
    TITLE = "CARTOGRAPHER"
    SUB_TITLE = "contacts on the local net"
    CSS = """
    Screen { background: #0b140d; color: #8dff9a; }
    Header { background: #12331a; color: #b6ff00; }
    Footer { background: #12331a; }
    #bar { height: 3; padding: 0 1; }
    #net { width: 24; }
    #filter { width: 1fr; }
    Input { background: #0f1f12; border: tall #2f7a3d; color: #b6ff00; }
    DataTable { background: #0b140d; height: 1fr; }
    DataTable > .datatable--header { background: #12331a; color: #b6ff00; text-style: bold; }
    DataTable > .datatable--cursor { background: #2f7a3d; color: #ffffff; }
    #status { height: 1; padding: 0 1; color: #ffb000; }
    ProgressBar { padding: 0 1; height: 1; }
    Bar > .bar--bar { color: #b6ff00; }
    """
    BINDINGS = [
        Binding("s", "scan", "Scan"),
        Binding("x", "stop", "Stop"),
        Binding("e", "export", "Export CSV"),
        Binding("p", "toggle_ports", "Ports on/off"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("escape", "focus_table", "Table", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, cidr: str | None = None, ports: bool = True, autoscan: bool = True):
        super().__init__()
        self.cidr = cidr
        self.ports = ports
        self.autoscan = autoscan
        self.hosts: dict[str, scan.Host] = {}
        self.sort_col = "ip"
        self.sort_rev = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="bar"):
            yield Input(self.cidr or "", placeholder="CIDR e.g. 10.8.2.0/24", id="net")
            yield Input(placeholder="/ filter by IP, name, MAC, vendor", id="filter")
        yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
        yield ProgressBar(total=100, show_eta=False, id="progress")
        yield Static("idle", id="status")
        yield Footer()

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        for key, label in COLUMNS:
            t.add_column(label, key=key)
        if not self.cidr:
            nets = scan.local_networks()
            if nets:
                self.cidr = str(nets[0][1].network)
                self.query_one("#net", Input).value = self.cidr
                self.status(f"auto-selected {nets[0][0]} {self.cidr}; other nets: "
                            + ", ".join(str(n[1].network) for n in nets[1:]) if len(nets) > 1 else "")
        t.focus()
        if self.autoscan and self.cidr:
            self.action_scan()

    def status(self, msg: str) -> None:
        self.query_one("#status", Static).update(msg)

    # ---- actions -------------------------------------------------------------------------
    def action_scan(self) -> None:
        cidr = self.query_one("#net", Input).value.strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
            scan.hosts_in(cidr)
        except ValueError as e:
            self.status(f"bad network: {e}")
            return
        self.cidr = cidr
        self.workers.cancel_group(self, "scan")
        self.hosts.clear()
        self.query_one(DataTable).clear()
        self.run_scan(cidr)

    def action_stop(self) -> None:
        self.workers.cancel_group(self, "scan")
        self.status("stopped")

    def action_toggle_ports(self) -> None:
        self.ports = not self.ports
        self.status(f"port probe {'on' if self.ports else 'off'} (applies to next scan)")

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_focus_table(self) -> None:
        self.query_one(DataTable).focus()

    def action_export(self) -> None:
        path = Path.home() / f"cartographer-{time.strftime('%Y%m%d-%H%M%S')}.csv"
        with path.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow([label for _, label in COLUMNS])
            for h in sorted(self.hosts.values(), key=lambda h: ipaddress.ip_address(h.ip)):
                w.writerow(self._row(h))
        self.status(f"exported {len(self.hosts)} hosts to {path}")

    # ---- scan worker ---------------------------------------------------------------------
    @work(group="scan", exclusive=True)
    async def run_scan(self, cidr: str) -> None:
        bar = self.query_one(ProgressBar)
        bar.update(total=100, progress=0)
        start = time.monotonic()
        alive = 0
        async for host, done, total in scan.sweep(cidr, ports=self.ports):
            bar.update(total=total, progress=done)
            if host.alive:
                alive += 1
                self.hosts[host.ip] = host
                self._upsert(host)
            self.status(f"sweeping {cidr}  {done}/{total}  contacts: {alive}")
        self.status(f"done: {alive} contacts on {cidr} in {time.monotonic() - start:.1f}s")

    def _row(self, h: scan.Host) -> list[str]:
        return [h.ip, h.hostname, h.mac, h.vendor, f"{h.rtt:.1f} ms" if h.rtt is not None else "-",
                _fmt_ports(h)]

    def _matches(self, h: scan.Host) -> bool:
        q = self.query_one("#filter", Input).value.strip().lower()
        return not q or any(q in c.lower() for c in self._row(h))

    def _upsert(self, h: scan.Host) -> None:
        if not self._matches(h):
            return
        self.query_one(DataTable).add_row(*self._row(h), key=h.ip)
        self._resort()

    def _resort(self) -> None:
        t = self.query_one(DataTable)
        if self.sort_col == "ip":
            t.sort("ip", key=lambda v: ipaddress.ip_address(v), reverse=self.sort_rev)
        else:
            t.sort(self.sort_col, key=lambda v: str(v).lower(), reverse=self.sort_rev)

    def _rebuild(self) -> None:
        t = self.query_one(DataTable)
        t.clear()
        for h in self.hosts.values():
            if self._matches(h):
                t.add_row(*self._row(h), key=h.ip)
        self._resort()

    # ---- events --------------------------------------------------------------------------
    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self._rebuild()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "net":
            self.action_scan()
        else:
            self.action_focus_table()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        key = event.column_key.value
        self.sort_rev = not self.sort_rev if key == self.sort_col else False
        self.sort_col = key
        self._resort()


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="cartographer", description="TUI network scanner (Advanced IP Scanner for the terminal)")
    ap.add_argument("cidr", nargs="?", help="network to sweep; default: first up interface")
    ap.add_argument("--no-ports", action="store_true", help="skip the port probe")
    ap.add_argument("--no-autoscan", action="store_true", help="wait for 's' before scanning")
    a = ap.parse_args()
    Cartographer(a.cidr, ports=not a.no_ports, autoscan=not a.no_autoscan).run()
    sys.exit(0)


if __name__ == "__main__":
    main()
