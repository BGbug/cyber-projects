import psutil
import subprocess
import socket
import platform
import csv
import re
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP
from prettytable import PrettyTable
import logging
import os
import requests
from bs4 import BeautifulSoup

# Configure logging to HTML
logging.basicConfig(filename='netscan.html', level=logging.INFO, format='%(message)s')
html_file = 'netscan.html'
malicious_ips_file = "known_malicious_ips.csv"
malicious_packet_found = False
malicious_ip = None

# Ensure HTML file has header
if not os.path.exists(html_file):
    with open(html_file, 'w') as file:
        file.write('<html><head><title>Network Scan Results</title></head><body>')
        file.write('<h1>Network Scan Results</h1>')

def load_known_malicious_ips(file_path):
    try:
        with open(file_path, 'r') as file:
            return [row[0] for row in csv.reader(file)]
    except Exception as e:
        logging.error(f"Error loading known malicious IPs from {file_path}: {e}")
        return []

def load_blocklist_ips(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        logging.error(f"Error loading blocklist from {url}: {e}")
        return []

known_malicious_ips = load_known_malicious_ips(malicious_ips_file)
blocklist_ips = load_blocklist_ips("https://lists.blocklist.de/lists/all.txt")

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def get_root_ip():
    while True:
        ip = input("Enter the IP address: ")
        if is_valid_ip(ip):
            return ip
        print("Invalid IP address. Please enter a valid IP address.")

def log_to_html(message):
    with open(html_file, 'a') as file:
        file.write(f'<p>{message}</p>')

def scan_network(root_ip):
    log_to_html("Scanning the network...")
    arp = ARP(pdst=root_ip + '/24')
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, timeout=2, verbose=False)[0]

    devices = [{'ip': rcv.psrc, 'mac': rcv.hwsrc, 'is_malicious': rcv.psrc in known_malicious_ips} for sent, rcv in result]
    return devices

def scan_ports(ip_address, ports):
    open_ports, closed_ports = [], []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip_address, port))
            (open_ports if result == 0 else closed_ports).append(port)
    return open_ports, closed_ports

def detect_os(ip_address):
    try:
        ports_to_scan = [22, 80, 443, 8080, 62078, 135, 3389]
        open_ports, _ = scan_ports(ip_address, ports_to_scan)
        
        if 62078 in open_ports:
            return "iOS"
        elif 80 in open_ports and 443 in open_ports:
            return "Android"
        elif 22 in open_ports:
            return "Linux"
        elif 135 in open_ports or 3389 in open_ports:
            return "Windows"
        return "Unknown"
    except Exception as e:
        log_to_html(f"Error detecting OS on {ip_address}: {e}")
        return "Error"

def display_connected_devices(devices):
    with open('top_100_ports.csv', 'r') as file:
        reader = csv.reader(file)
        next(reader)
        top_100_ports = [int(row[0]) for row in reader]

    log_to_html("Connected devices:")
    table = PrettyTable(["IP Address", "MAC Address", "Open Ports", "Closed Ports", "OS Detected", "Malicious"])
    
    for device in devices:
        ip_address = device['ip']
        open_ports, closed_ports = scan_ports(ip_address, top_100_ports)
        os_detected = detect_os(ip_address)

        table.add_row([
            ip_address,
            device['mac'],
            ', '.join(map(str, open_ports)),
            ', '.join(map(str, closed_ports)),
            os_detected,
            "Yes" if device['is_malicious'] else "No"
        ])

    log_to_html(table.get_html_string())

def check_updates():
    log_to_html("<br>Checking for outdated or unpatched software...")
    system = platform.system()
    
    try:
        if system == "Linux":
            result = subprocess.run(['apt-get', '-s', 'upgrade'], capture_output=True, text=True)
            outdated_software = result.stdout
            if 'not upgraded' in outdated_software:
                if input("Outdated software found. Do you want to update it (Y/N): ").strip().lower() in ('y', 'yes'):
                    log_to_html("Updating all outdated software...")
                    result = subprocess.run(['apt-get', 'upgrade', '-y'], capture_output=True, text=True)
                    log_to_html(result.stdout)
            else:
                log_to_html("All packages are up to date.<br>")
        elif system == "Windows":
            result = subprocess.run(["winget", "upgrade"], capture_output=True, text=True)
            outdated_software = result.stdout
            if "upgrades available" in outdated_software:        
                if input("Outdated software found. Do you want to update it (Y/N): ").strip().lower() in ('y', 'yes'):
                    log_to_html("Updating all outdated software...")
                    result = subprocess.run(["winget", "upgrade", "--all"], capture_output=True, text=True)
                    log_to_html(result.stdout)
        else:
            log_to_html(f"Unsupported OS: {system}")
    except Exception as e:
        log_to_html(f"Error checking updates on {system}: {e}<br>")

def check_firewall():
    log_to_html("Checking firewall configuration...")
    try:
        system = platform.system()
        if system == "Linux":
            result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, check=True)
            log_to_html(result.stdout)

            if "Status: inactive" in result.stdout:
                log_to_html("Warning!!! Firewall is inactive.")
                if input("Do you want to activate the firewall? (y/n): ").strip().lower() == 'y':
                    log_to_html("Activating firewall...")
                    result = subprocess.run(['ufw', 'enable'], capture_output=True, text=True, check=True)
                    log_to_html("Firewall has been activated.")
            else:
                log_to_html("Firewall is active and configured properly.")
        else:
            log_to_html(f"Firewall check is not supported on {system}.")
    except subprocess.CalledProcessError as e:
        log_to_html(f"Command failed with error code {e.returncode}: {e.output}")
    except Exception as e:
        log_to_html(f"Error checking firewall: {e}")

def block_ip(ip):
    log_to_html(f"Blocking IP: {ip}")
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        log_to_html(f"IP {ip} has been blocked.")
    except subprocess.CalledProcessError as e:
        log_to_html(f"Failed to block IP {ip}: {e}")
    except Exception as e:
        log_to_html(f"Error blocking IP {ip}: {e}")

def detect_malicious_packet(packet):
    global malicious_packet_found, malicious_ip
    if IP in packet:
        ip_src, ip_dst = packet[IP].src, packet[IP].dst

        if ip_src in known_malicious_ips or ip_dst in known_malicious_ips:
            malicious_packet_info = f"Malicious IP detected! Source: {ip_src}, Destination: {ip_dst}"
            log_to_html(malicious_packet_info)
            malicious_packet_found = True
            malicious_ip = ip_src if ip_src in known_malicious_ips else ip_dst

        if TCP in packet and packet[TCP].flags == 0x02:  # SYN flag
            malicious_packet_info = f"SYN packet detected from {ip_src} to {ip_dst}"
            log_to_html(malicious_packet_info)
            malicious_packet_found = True
            malicious_ip = ip_src if ip_src in known_malicious_ips else ip_dst

        if UDP in packet:
            malicious_packet_info = f"UDP packet detected from {ip_src} to {ip_dst}"
            log_to_html(malicious_packet_info)
            malicious_packet_found = True
            malicious_ip = ip_src if ip_src in known_malicious_ips else ip_dst

def start_packet_sniffing(interfaces):
    for interface in interfaces:
        if interface in psutil.net_if_addrs():
            log_to_html(f"Starting packet sniffing on {interface}...")
            try:
                sniff(iface=interface, prn=detect_malicious_packet, stop_filter=lambda x: malicious_packet_found, store=0)
            except Exception as e:
                log_to_html(f"Error starting sniffing on {interface}: {e}")
        else:
            log_to_html(f"Interface {interface} not found.")

def main():
    root_ip = get_root_ip()
    devices = scan_network(root_ip)
    display_connected_devices(devices)

    interfaces = ['eth0', 'wlan0']
    start_packet_sniffing(interfaces)

    if malicious_packet_found:
        log_to_html("Malicious packet found. Sniffing stopped.")
        log_to_html(f"Detected malicious activity.")
        print(f"Detected malicious activity.")
        if input(f"Malicious IP {malicious_ip} detected. Do you want to block it? (y/n): ").strip().lower() == 'y':
            block_ip(malicious_ip)
        else:
            log_to_html("Malicious IP not blocked.")
    else:
        log_to_html("No malicious packets found.")

    check_updates()
    check_firewall()

    # Compare the list with blocklist IPs and notify the user
    log_to_html("Comparing against blocklist IPs...")
    for ip in blocklist_ips:
        if ip in known_malicious_ips:
            log_to_html(f"IP {ip} found in blocklist. Malicious.")
        else:
            log_to_html(f"IP {ip} not found in blocklist.")

    with open(html_file, 'a') as file:
        file.write('</body></html>')

if __name__ == '__main__':
    main()
