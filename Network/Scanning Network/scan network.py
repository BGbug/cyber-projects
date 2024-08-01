import socket
import subprocess
import platform

def check_open_ports(ip):
    open_ports = []
    for port in range(1, 1024):  # Check common ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def get_connected_devices():
    devices = []
    # Use arp -a command to list all devices connected to the network
    output = subprocess.check_output(['arp', '-a']).decode()
    lines = output.split('\n')
    for line in lines:
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1].strip('()')
                devices.append(ip)
    return devices

def get_os_info(ip):
    try:
        # Ping the target IP and analyze the TTL value
        output = subprocess.check_output(['ping', '-c', '1', ip]).decode()
        for line in output.split('\n'):
            if 'ttl=' in line.lower():
                ttl = int(line.split('ttl=')[1].split()[0])
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return "Unknown"

        # Try to determine if the device is Android or iOS by looking at the MAC address vendor
        output = subprocess.check_output(['arp', '-a', ip]).decode()
        if "Android" in output:
            return "Android"
        elif "Apple" in output:
            return "iOS"
    except subprocess.CalledProcessError:
        return "Unknown"
    return "Unknown"

def get_ethernet_driver():
    # Get Ethernet driver information using ethtool (Linux only)
    if platform.system() == "Linux":
        interface = "eth0"  # Change according to your system's interface name
        output = subprocess.check_output(['ethtool', '-i', interface]).decode()
        for line in output.split('\n'):
            if 'driver:' in line:
                return line.split('driver:')[1].strip()
    return "Unknown"

if __name__ == "__main__":
    target_ips = input("Enter the target IP addresses (to add multiple ipaddress give whitespace then add): ").split()

    for target_ip in target_ips:
        print(f"\nGathering information for {target_ip}...\n")

        print("Checking open ports...")
        open_ports = check_open_ports(target_ip)
        print(f"Open ports on {target_ip}: {open_ports}")

        print("Getting connected devices...")
        devices = get_connected_devices()
        print(f"Devices connected to the network: {devices}")

        print("Getting operating system information...")
        os_info = get_os_info(target_ip)
        print(f"Operating system of {target_ip}: {os_info}")

        print("Getting Ethernet driver information...")
        ethernet_driver = get_ethernet_driver()
        print(f"Ethernet driver: {ethernet_driver}")