# port-scanner
Port scanner written in Python for Linux
The scanner uses scapy to create and send the packets and uses pdflatex (optional) to generate pdf reports of the output. The script requires root privileges for full functionality.

Usage: ./scan.py [ip-address(es)] [FLAGS]

Ip Address Format:

IP_ADDRESS_RANGE[/NETMASK][:PORTS]
The scanner is fairly flexible in how it accepts IP addresses and will accept ip address ranges or comma-separated values in any octet of the address. It also allows optionally specifying a netmask by using / and then then netmask size. Also optional is specifying the ports to be scanned by using a colon and then a either a single port, a range of ports, or comma-separated ports. If no ports are specified, a default set of ports will be used.

For example:
192.168.100,207-209.0/24:1-1024,8080 192.168.207.42:8081 would scan port ports 1-1024 and port 8080 on all machines on 192.168.100.0/24, 192.168.207.0/24, 192.168.208.0/24, and 192.168.209.0/24. In addition it would also scan port 8081 on 192.168.207.42.

Flags:

-h - displays a help message with a list of all flags

-O CREATE_PDF - creates a pdf with the program's output if pdflatex is installed with the specified filename

-g SOURCE_PORT - specifies which port to send packets from

-S SOURCE_ADDRESS - specifies which address to spoof packets being from (you probably just won't get anything back)

-sn, --icmp - Run an ICMP scan on the machines specified (Default if no other types of scans are specified)

-T, --traceroute - Run a traceroute on the machines specified

-sT, --tcp - Run a TCP scan on the machines specified

-sU, --udp - Run a UDP scan on the machines specified

-sX, --christmas - Run a TCP Christmas Scan on the machines specified

-v, --verbose - Enable verbose output
