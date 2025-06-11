import socket
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, ICMP, sr1
from colorama import init, Fore, Style
init(autoreset=True)

# ==============
# Services dictionary
# ==============

probe_dict = {
    21: b'HELP\r\n',              # FTP
    22: b'SSH-2.0-OpenSSH_7.4\r\n',  # SSH (just send version string)
    25: b'HELO example.com\r\n',  # SMTP
    80: b'GET / HTTP/1.0\r\n\r\n',  # HTTP
    110: b'QUIT\r\n',             # POP3
    143: b'LOGIN username password\r\n',  # IMAP
    443: b'GET / HTTP/1.0\r\n\r\n', # HTTPS (will likely fail without SSL support, unless you wrap socket)
}



# ===================
# Parse CLI arguments
# ===================
def parse_args():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="IP address or subnet")
    parser.add_argument("-p", "--port", type=int, help="Port to scan (default: scan port 1-1024)", default=None)
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use")
    parser.add_argument("-a", "--all-ports", action="store_true", help="Scan all 65535 TCP ports")
    return parser.parse_args()

# ========
# Identifying services base on probe_dict
# ========
def identify_service(sock, port):
    try:
        if port == 80 or port == 8080:
            # Send proper HTTP HEAD request to get detailed Server info
            http_probe = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            sock.sendall(http_probe)
            response = sock.recv(1024).decode(errors='ignore')

            #Look for the Server header
            for line in response.split('\r\n'):
                if line.lower().startswith("server:"):
                    return line 
            return "HTTP service detected, but no Server header"
         
        elif port in probe_dict:
            sock.sendall(probe_dict[port])
            return sock.recv(1024).decode(errors='ignore').strip()
        
        else:
            # For ports not in probe_dict, try generic banner grabbing
            return sock.recv(1024).decode(errors='ignore').strip()
        
    except Exception:
        return None
    

# ===========
# Detect OS, but VERY LIMITED AND SIMPLE as it's using default TTL for different systems. Apparently not as noisy for IDS
# ===========
def detect_os(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)

        if resp is None:
            return "No response (possibly filtered)"

        ttl = resp.ttl

        if ttl <= 64:
            return "Linux/Unix (TTL: {})".format(ttl)
        elif ttl <= 128:
            return "Windows (TTL: {})".format(ttl)
        elif ttl <= 255:
            return "Network Device (e.g., Cisco) (TTL: {})".format(ttl)
        else:
            return f"Unknown OS (TTL: {ttl})"
    
    except Exception as e:
        return f"OS detection failed: {e}"
    

# =======
# Port scanning function
# =======
def scan_port(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        result = s.connect_ex((str(ip), port))
        if result == 0:
            service_info = identify_service(s, port)
            return (port, service_info)
        s.close()
    
    except:
        pass
    return None

# =========
# Main Scanning logic
# =========
def scan_host(ip, port_range, threads):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for port in port_range:
            executor.submit(scan_port, ip, port)
            
# ==================
# Main function
# ==================
def main():   #MODIFY THIS - REFER TO GPT
    args = parse_args()
    
    try:
        targets = ipaddress.ip_network(args.target, strict=False)
    except ValueError as e:
        print(f"Invalid IP/Subnet: {e}")
        return
    
    if args.all_ports:
        port_range = range(1, 65536)
    else:
        port_range = [args.port] if args.port else range(1, 1025)

    for ip in targets.hosts():
        print(f"\n[*] Scanning {ip} ...")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(scan_port, str(ip), port) for port in port_range]

            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)

        # OS detection
        os_guess = detect_os(str(ip))
        os_colored = Fore.MAGENTA + os_guess
        print(f"[OS] Detected OS for {ip}: {os_colored}")
        
        for port, banner in sorted(open_ports):
            # Add colors for print
            ip_colored = Fore.CYAN + str(ip)
            port_colored = Fore.GREEN + str(port)
            banner_colored = Fore.YELLOW + banner if banner else ""

            service_info = f"| {banner_colored}" if banner else ""
            print(f"[+] {ip_colored}:{port_colored} is open {service_info}")

if __name__ == "__main__":
    main()


