"""Scan engine: ping sweep, neighbour-table MACs, OUI vendors, hostnames, ports.

Runs unprivileged. Sending an ICMP echo (or any packet) makes the kernel ARP for the
target, so the neighbour table tells us which hosts exist even when they drop ICMP.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import shutil
import socket
import struct
from dataclasses import dataclass, field
from typing import AsyncIterator

OUI_FILE = "/usr/share/ieee-data/oui.txt"
PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 135: "rpc", 139: "netbios",
         161: "snmp", 443: "https", 445: "smb", 3389: "rdp", 5060: "sip", 8080: "http-alt"}
MAX_HOSTS = 4096


@dataclass
class Host:
    ip: str
    alive: bool = False
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    rtt: float | None = None
    ports: list[int] = field(default_factory=list)


_oui: dict[str, str] = {}


def vendor_for(mac: str) -> str:
    if not _oui:
        try:
            with open(OUI_FILE, errors="replace") as f:
                for line in f:
                    m = re.match(r"^\s*([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$", line)
                    if m:
                        _oui["".join(m.groups()[:3])] = m.group(4)
        except OSError:
            _oui["_"] = ""
    prefix = mac.replace(":", "").upper()[:6]
    first = int(prefix[:2], 16) if len(prefix) >= 2 else 0
    if first & 0x02:  # locally administered: randomised/virtual MAC
        return "(private MAC)"
    return _oui.get(prefix, "")


def local_networks() -> list[tuple[str, ipaddress.IPv4Interface]]:
    """Up IPv4 interfaces, skipping loopback and docker bridges."""
    import subprocess
    out = subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True).stdout
    nets = []
    for ifc in json.loads(out or "[]"):
        if ifc["ifname"] == "lo" or ifc["ifname"].startswith(("docker", "br-", "veth")):
            continue
        if "UP" not in ifc.get("flags", []):
            continue
        for a in ifc.get("addr_info", []):
            nets.append((ifc["ifname"], ipaddress.IPv4Interface(f"{a['local']}/{a['prefixlen']}")))
    return nets


async def _run(*cmd: str, timeout: float = 3) -> str:
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
        return out.decode(errors="replace")
    except (asyncio.TimeoutError, OSError):
        return ""


async def _ping(ip: str) -> float | None:
    out = await _run("ping", "-c1", "-W1", ip, timeout=3)
    m = re.search(r"time=([\d.]+) ms", out)
    return float(m.group(1)) if m else None


async def _neigh_mac(ip: str) -> str:
    out = await _run("ip", "-j", "neigh", "show", ip)
    try:
        for n in json.loads(out or "[]"):
            if n.get("lladdr") and not {"FAILED", "INCOMPLETE"} & set(n.get("state", [])):
                return n["lladdr"].lower()
    except json.JSONDecodeError:
        pass
    return ""


async def _rdns(ip: str) -> str:
    try:
        name = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(
            None, socket.gethostbyaddr, ip), 2)
        return name[0]
    except (asyncio.TimeoutError, OSError):
        return ""


async def _mdns(ip: str) -> str:
    if not shutil.which("avahi-resolve"):
        return ""
    out = await _run("avahi-resolve", "-a", ip, timeout=2)
    parts = out.split()
    return parts[1] if len(parts) >= 2 else ""


class _NbtProto(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future):
        self.fut = fut

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)


async def _netbios(ip: str) -> str:
    """NBSTAT wildcard query on UDP/137; returns the workstation name if any."""
    q = struct.pack(">HHHHHH", 0x1337, 0, 1, 0, 0, 0) + b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
        + b"\x00" + struct.pack(">HH", 0x21, 1)
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _NbtProto(fut), remote_addr=(ip, 137))
    except OSError:
        return ""
    try:
        transport.sendto(q)
        data = await asyncio.wait_for(fut, 1.0)
        # header 12 + name 34 + type/class 4 + ttl 4 + rdlen 2 = 56, then count, then 18-byte entries
        count = data[56]
        for i in range(count):
            e = data[57 + 18 * i: 57 + 18 * (i + 1)]
            if len(e) == 18 and e[15] == 0x00 and not struct.unpack(">H", e[16:18])[0] & 0x8000:
                return e[:15].decode(errors="replace").strip()
    except (asyncio.TimeoutError, IndexError, OSError):
        pass
    finally:
        transport.close()
    return ""


async def _port(ip: str, port: int) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 0.8)
        w.close()
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def _probe(ip: str, ports: bool) -> Host:
    h = Host(ip)
    h.rtt = await _ping(ip)
    h.mac = await _neigh_mac(ip)
    h.alive = h.rtt is not None or bool(h.mac)
    if not h.alive:
        return h
    if h.mac:
        h.vendor = vendor_for(h.mac)
    res = await asyncio.gather(_rdns(ip), _mdns(ip), _netbios(ip))
    h.hostname = next((r for r in res if r), "")
    if ports:
        hits = await asyncio.gather(*(_port(ip, p) for p in PORTS))
        h.ports = [p for p, ok in zip(PORTS, hits) if ok]
    return h


def hosts_in(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"{net} has {net.num_addresses} addresses; limit is {MAX_HOSTS}")
    return [str(h) for h in (net.hosts() if net.prefixlen < 31 else net)]


def auto_networks() -> list[str]:
    """Every connected network (main LAN, VPN, ...), de-duplicated, in interface order."""
    return list(dict.fromkeys(str(i.network) for _, i in local_networks()))


def parse_networks(text: str) -> list[str]:
    """Split on commas/spaces. 'auto' expands to the connected networks; bare IPs become /32.
    Raises ValueError on a bad entry or a network over MAX_HOSTS."""
    out: list[str] = []
    for tok in re.split(r"[,\s]+", text.strip()):
        if not tok:
            continue
        if tok.lower() == "auto":
            out += auto_networks()
            continue
        net = ipaddress.ip_network(tok, strict=False)
        hosts_in(str(net))  # size check
        out.append(str(net))
    return list(dict.fromkeys(out))


async def sweep(cidrs: str | list[str], ports: bool = True,
                concurrency: int = 96) -> AsyncIterator[tuple[Host, int, int]]:
    """Yield (host, done, total) for every address as it finishes; filter on host.alive."""
    if isinstance(cidrs, str):
        cidrs = [cidrs]
    targets = list(dict.fromkeys(ip for c in cidrs for ip in hosts_in(c)))
    sem = asyncio.Semaphore(concurrency)

    async def one(ip: str) -> Host:
        async with sem:
            return await _probe(ip, ports)

    tasks = [asyncio.create_task(one(ip)) for ip in targets]
    try:
        for done, fut in enumerate(asyncio.as_completed(tasks), 1):
            yield await fut, done, len(tasks)
    finally:
        for t in tasks:
            t.cancel()
