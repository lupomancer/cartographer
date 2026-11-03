# Cartographer

TUI network scanner, a terminal take on Advanced IP Scanner. Sweeps a subnet and lists IP, hostname (DNS, mDNS, NetBIOS), MAC, manufacturer (OUI), RTT and open common ports. Runs unprivileged; MACs come from the kernel neighbour table, so hosts that drop ICMP still show up.

    cartographer                          # sweeps every connected network (LAN, VPN, ...)
    cartographer 10.8.2.0/24 192.168.1.0/24   # only these networks
    cartographer --auto 172.16.5.0/24     # connected networks plus these
    cartographer --no-ports

The network box in the UI takes the same thing: comma or space separated CIDRs or IPs, and `auto` for the connected networks (`auto, 172.16.5.0/24` = defaults plus one more). Press Enter or `s` to rescan. Each network is capped at 4096 addresses.

Keys: s scan, x stop, / filter, e export CSV to ~, p toggle port probe, click a header to sort, q quit.
Requires python3, `ip`, `ping`, and `.venv` with textual (`python3 -m venv .venv && .venv/bin/pip install textual`). Vendors need /usr/share/ieee-data/oui.txt (package ieee-data). Optional: avahi-resolve for mDNS names.
