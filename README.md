# Cartographer

TUI network scanner, a terminal take on Advanced IP Scanner. Sweeps a subnet and lists IP, hostname (DNS, mDNS, NetBIOS), MAC, manufacturer (OUI), RTT and open common ports. Runs unprivileged; MACs come from the kernel neighbour table, so hosts that drop ICMP still show up.

    ./cartographer.sh              # auto-picks first up interface
    ./cartographer.sh 10.8.2.0/24  # explicit network
    ./cartographer.sh --no-ports

Keys: s scan, x stop, / filter, e export CSV to ~, p toggle port probe, click a header to sort, q quit.
Requires python3, `ip`, `ping`, and `.venv` with textual (`python3 -m venv .venv && .venv/bin/pip install textual`). Vendors need /usr/share/ieee-data/oui.txt (package ieee-data). Optional: avahi-resolve for mDNS names.
