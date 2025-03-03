import sys
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from tqdm import tqdm
import argparse

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]


def get_local_ip():
    hostname = socket.gethostname()
    ips = socket.gethostbyname_ex(hostname)[2]
    for ip in ips:
        if not ip.startswith("127."):
            return ip
    return "127.0.0.1"


# List all IP addresses and hostnames on the local subnet
def scan_subnet():
    local_ip = get_local_ip()
    # Assume a /24 network from the local IP
    network = ipaddress.ip_network("{}.0/24".format(".".join(local_ip.split(".")[:-1])), strict=False)
    active_ips = []

    # Ping sweep using ping command (may miss devices that drop ICMP)
    def ping_host(ip):
        result = subprocess.run(["ping", "-n", "1", "-w", "1000", str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0: active_ips.append(str(ip))

    with ThreadPoolExecutor(max_workers=2000) as executor: list(executor.map(ping_host, list(network.hosts())))

    try:
        # Use nmap ping scan to catch hosts that didn't respond to ICMP
        nmap_output = subprocess.run(["nmap", "-sn", str(network)], stdout=subprocess.PIPE, text=True).stdout
        # Updated regex to capture IP with or without hostname in parentheses
        nmap_ips = set(re.findall(r"Nmap scan report for (?:[^\(]+\()?(\d+\.\d+\.\d+\.\d+)\)?", nmap_output))
    except Exception:
        nmap_ips = set()

    # Retrieve ARP table mapping (IP -> MAC)
    arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, text=True).stdout
    arp_mapping = dict(re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})", arp_output))
    
    # Merge IPs from ping sweep, ARP table, and nmap scan
    all_ips = set(active_ips) | set(arp_mapping.keys()) | nmap_ips
    
    for ip in sorted(all_ips, key=lambda a: list(map(int, a.split(".")))):
        mac = arp_mapping.get(ip, "Unknown")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown"
        print(f"{ip:<15} || {mac:<17} || {hostname}")


def get_arp_table():
    arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, text=True).stdout
    return dict(re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})", arp_output))


def is_ipv4(target): return re.match(r"^\d+\.\d+\.\d+\.\d+$", target)
def is_mac(target): return re.match(r"^(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$", target)


# Take in IP address, MAC address, or hostname and resolve to all three
def resolve_target(target):
    arp_table = get_arp_table()
    result = {"ip": None, "mac": "Unknown", "hostname": "Unknown"}
    if is_ipv4(target):
        result["ip"] = target
        result["mac"] = arp_table.get(target, "Unknown")
        try:
            result["hostname"] = socket.gethostbyaddr(target)[0]
        except Exception:
            pass
    elif is_mac(target):
        for ip, mac in arp_table.items():
            if mac.lower() == target.lower():
                result["ip"] = ip
                result["mac"] = mac
                try:
                    result["hostname"] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                break
        else:
            result["mac"] = target
    else:
        try:
            ip = socket.gethostbyname(target)
            result["ip"] = ip
            result["mac"] = arp_table.get(ip, "Unknown")
            result["hostname"] = target
        except Exception:
            result["hostname"] = target
    return result


def scan_host(target):
    res = resolve_target(target)
    print(f"---------------------------------")
    print(f"IP Address  : {res['ip']}")
    print(f"MAC Address : {res['mac']}")
    print(f"Hostname    : {res['hostname']}")
    print(f"---------------------------------")


# Scan a target for open ports; mode can be 'all' or 'common'. Defaults to common.
def port_scan(target, mode="all"):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Unable to resolve {target}")
        return

    print(f"Scanning {target} ({ip})...")

    if mode == "all": ports = list(range(1, 65536))
    elif mode == "common": ports = COMMON_PORTS
    else: ports = COMMON_PORTS
    
    open_ports = []

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)

    # TODO: Change max_workers based on device capabilities
    with ThreadPoolExecutor(max_workers=2000) as executor:
        futures = [executor.submit(scan_port, port) for port in ports]
        for _ in tqdm(as_completed(futures), total=len(futures), desc="Scanning ports"):
            pass

    if open_ports:
        print("\nOpen ports:")
        for port in sorted(open_ports):
            print(port)
    else:
        print("No open ports found.")


# Use nmap to extract OS information of a target
def os_info(target):
    res = resolve_target(target)
    if not res["ip"]:
        print("Unable to resolve host to an IP address.")
        return
    ip = res["ip"]
    try:
        nmap_output = subprocess.run(["nmap", "-O", "-Pn", ip],
                                     stdout=subprocess.PIPE, text=True).stdout
        mac_info = None
        os_cpe = None
        aggressive_guesses = None
        
        for line in nmap_output.splitlines():
            line = line.strip()
            if line.startswith("MAC Address:"):
                mac_info = line[len("MAC Address:"):].strip()
            elif line.startswith("OS CPE:"):
                cpe_line = line[len("OS CPE:"):].strip()
                # Split using comma if present; otherwise, use regex for space-separated CPEs.
                if ',' in cpe_line:
                    cpe_entries = [cpe.strip() for cpe in cpe_line.split(",") if cpe.strip()]
                else:
                    cpe_entries = re.findall(r"(cpe:[^\s]+)", cpe_line)
                os_cpe = cpe_entries if cpe_entries else None
            elif line.startswith("Aggressive OS guesses:"):
                aggressive_guesses = [guess.strip() for guess in line.split(":",1)[1].split(",")]
        
        print(f"---------------------------------")
        if mac_info:
            print(f"MAC Address: {mac_info}")
        if os_cpe:
            print("OS CPE:")
            for cpe in os_cpe:
                print(f"  - {cpe}")
        if aggressive_guesses:
            print("Aggressive OS Guesses:")
            for guess in aggressive_guesses:
                print(f"  - {guess}")
        print(f"---------------------------------")
    except FileNotFoundError:
        print("nmap not found. Please install nmap to enable OS detection.")


# Scans a target for Windows shares using nmap. Returns a list of dictionaries containing share names and network addresses.
# TODO: Clean up output
def share_scan(target):
    # If target is a network (CIDR), use it as is; otherwise, resolve to IP.
    if "/" not in target:
        res = resolve_target(target)
        if not res["ip"]:
            print("Unable to resolve host to an IP address.")
            return
        ip = res["ip"]
    else:
        ip = target
    print(f"Scanning for Windows shares on {target} ({ip})...")
    try:
        nmap_output = subprocess.run(
            ["nmap", "-p139,445", "--script", "nbstat,smb-enum-shares", ip],
            stdout=subprocess.PIPE, text=True).stdout

        # Use a verbose, multi-line regex to capture share details
        pattern = re.compile(r"""
            \\{2}\S+\\(?P<share>\S+):\s*\n       # line with UNC share name
            \s*\|.*?Type:\s*(?P<type>[^\n]+)\s*\n  # Type field
            \s*\|.*?Comment:\s*(?P<comment>[^\n]+)\s*\n  # Comment field
            \s*\|.*?Anonymous\s+access:\s*(?P<anon>[^\n]+)\s*\n  # Anonymous access field
            \s*\|.*?Current\s+user\s+access:\s*(?P<current>[^\n]+)\s*\n
            """, re.VERBOSE | re.MULTILINE)
        
        shares = []
        for match in pattern.finditer(nmap_output):
            share = {
                "name": match.group("share").strip(),
                "type": match.group("type").strip(),
                "comment": match.group("comment").strip(),
                "anonymous": match.group("anon").strip(),
                "current": match.group("current").strip(),
                "address": f"\\\\{ip}\\{match.group('share').strip()}"
            }
            shares.append(share)
        
        if shares:
            print("Windows Shares Found:")
            print("---------------------------------------------------")
            for s in shares:
                print(f"Share Name           : {s['name']}")
                print(f"Share Address        : {s['address']}")
                print(f"Type                 : {s['type']}")
                print(f"Comment              : {s['comment']}")
                print(f"Anonymous Access     : {s['anonymous']}")
                print(f"Current User Access  : {s['current']}")
                print("---------------------------------------------------")
        else:
            print("No Windows shares found.")
            print("Raw nmap output for debugging:")
            print(nmap_output)
    except FileNotFoundError:
        print("nmap not found. Please install nmap to enable share scanning.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Swiss Network Tool v1.0.1")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Subparser for listing subnet hosts
    list_parser = subparsers.add_parser("list", help="List IP addresses & hostnames on local subnet")
    
    # Subparser for portscan command
    port_parser = subparsers.add_parser("portscan", help="Scan a target for open ports")
    port_parser.add_argument("target", help="Target hostname or IP")
    port_parser.add_argument("--mode", choices=["all", "common"], default="common", help="Scan mode: 'all' scans all ports, 'common' scans common ports. Defaults to common.")
    
    # Subparser for resolve command
    resolve_parser = subparsers.add_parser("resolve", help="Resolve a target (IP, MAC, or hostname) to its corresponding values")
    resolve_parser.add_argument("target", help="Input MAC address, IP address, or hostname")
    
    # New subparser for OS information command
    osinfo_parser = subparsers.add_parser("os", help="Get OS information of a host (by IP, MAC, or hostname)")
    osinfo_parser.add_argument("target", help="Input MAC address, IP address, or hostname")
    
    # New subparser for share scanning
    smb_parser = subparsers.add_parser("shares", help="Scan for SMB shares on a host or network (CIDR accepted)")
    smb_parser.add_argument("target", help="Input MAC address, IP address, hostname, or CIDR (e.g., 192.168.1.0/24)")
    
    args = parser.parse_args()

    if args.command == "list":          scan_subnet()
    elif args.command == "portscan":    port_scan(args.target, mode=args.mode)
    elif args.command == "resolve":     scan_host(args.target)
    elif args.command == "os":          os_info(args.target)
    elif args.command == "shares":      share_scan(args.target)