The script checks...

1.Check Open Ports: 
The check_open_ports function scans common ports (1-1024) on a specified IP address to check if they are open. It does this by attempting to establish a socket connection to each port and records the open ports.

2.Get Connected Devices:
The get_connected_devices function uses the arp -a command to list all devices connected to the network. It parses the command output to extract and return the IP addresses of connected devices.

3.Get OS Information:
The get_os_info function tries to determine the operating system of a specified IP by analyzing the Time-To-Live (TTL) value from a ping command. It uses the TTL value to infer if the OS is likely Linux/Unix or Windows. Additionally, it checks the output of the arp -a command for indications that the device might be Android or iOS, based on MAC address vendor information.

4.Get Ethernet Driver Information:
The get_ethernet_driver function retrieves Ethernet driver information using the ethtool -i command, which works on Linux systems. It extracts the driver name from the command output.

Input (0.0.0.0) - for single IP address
      (0.0.0.0 0.0.0.0 ... ) - for multiple ip address