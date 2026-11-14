# Cartographer

TUI network scanner, a terminal take on Advanced IP Scanner. Sweeps a subnet and lists IP, hostname (DNS, mDNS, NetBIOS), MAC, manufacturer (OUI), RTT and open common ports. Runs unprivileged; MACs come from the kernel neighbour table, so hosts that drop ICMP still show up.

    cartographer                          # sweeps every connected network (LAN, VPN, ...)
    cartographer 10.8.2.0/24 192.168.1.0/24   # only these networks
    cartographer --auto 172.16.5.0/24     # connected networks plus these
    cartographer --no-ports

The network box in the UI takes the same thing: comma or space separated CIDRs or IPs, and `auto` for the connected networks (`auto, 172.16.5.0/24` = defaults plus one more). Press Enter or `s` to rescan. Each network is capped at 4096 addresses.

Keys: s scan, x stop, / filter, e export CSV to ~, p toggle port probe, click a header to sort, q quit.
Install: run `./cartographer.sh` once. It builds `.venv` itself (uv if present, else python3 -m venv; Debian needs `python3-venv`) and, on an interactive run, asks whether to install a `cartographer` command system-wide (symlink in /usr/local/bin via sudo, or ~/.local/bin without sudo). Answer `never` to stop the prompt. `./cartographer.sh --install` / `--uninstall` do it by hand.

Requires python3, `ip`, `ping`. Vendors need /usr/share/ieee-data/oui.txt (package ieee-data). Optional: avahi-resolve for mDNS names.
