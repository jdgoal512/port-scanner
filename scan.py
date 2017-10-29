#!/bin/python

#NOTE: This script only runs in Linux and requires pdflatex in order to create pdfs

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#The default ports to scan in none are specified
default_ports = [20,21,22,23,25,53,67,68,69,79,80,88,110,123,135,137,138,139,143,161,162,179,389,445,464,593,636,989,990,1025,1026,1039,1070,1234,2222,3268,3389,8000,8080,8081,8888]

#Maps port numbers to services
PORT_LOOKUP = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())

#ANSI color codes for colored output
NORMAL = "\033[0m";
BOLD = "\033[1m";
RED = "\033[31m";
GREEN = "\033[32m";
YELLOW = "\033[33m";
BLUE = "\033[34m";
PURPLE = "\033[35m";
CYAN = "\033[36m";
WHITE = "\033[39m";

#Verbose mode
verboseMessages = True

#Whether or not to make a pdf of the output
create_pdf = False

def printMessage(text, formatting = WHITE):
    print(formatting + text + WHITE + NORMAL)
    #Output to tex file if creating pdf
    if create_pdf:
        #Turn bold messages into section titles
        if BOLD in formatting:
            os.system("echo \"\section{" + text.replace("_", "\_") + "}\" >> temp.tex") 
        else:
            os.system("echo -n \'" + text.replace("_", "\_") + '\\' + "\' >> temp.tex") 
            os.system("echo \'\\\' >> temp.tex") 

#Prints a message if in verbose mode, otherwise does nothing
def verboseMessage(output, formatting = ""):
    if (verboseMessages):
        printMessage(output, formatting)

#Represents a machine and has an ip address and a list of ports
class Target:

    def __init__(self, host, ports):
        self.host = host
        self.ports = ports

    def toString(self):
        output = "";
        for port in self.ports:
            output = output + self.host + ":" + str(port) + "\n"
        return output[:-1]

    #Run ICMP Scan on this machine
    def runICMP(self, sender):
        verboseMessage("Scanning " + self.host)
        #Make sure you have the correct permissions to run the scan
        try:
            reply = sr1(IP(dst=self.host)/ICMP(), timeout = 1, verbose=0)
        except PermissionError:
            printMessage("ERROR: You do not have the needed permissions to run this scan, try running the script as root", RED)
            return
        if (reply):
            printMessage(self.host + " is up")
        else:
            verboseMessage(self.host + " could not be reached", RED)

    #Run TCP Scan on this machine
    def runTCP(self, sender):
        global PORT_LOOKUP
        send_port = int(sender.ports[-1])
        #Run scan on each port
        for port in self.ports:
            #Make sure you have the correct permissions to run the scan
            try:
                reply = sr1(IP(dst=self.host)/TCP(sport=send_port, dport=int(port)), timeout = 1, verbose=0)
            except PermissionError:
                printMessage("ERROR: You do not have the needed permissions to run this scan, try running the script as root", RED)
                return
            if reply:
                flags = reply.getlayer(TCP).flags
                if flags == 18: #SYNACK = 18
                    printMessage(self.host + ":" + port + " is open [" + PORT_LOOKUP[int(port)] +"]")
                else:
                    verboseMessage(self.host + ":" + port + " is closed", RED)
            else:
                verboseMessage(self.host + ":" + port + " is closed", RED)

    #Run UDP Scan on this machine
    def runUDP(self, sender):
        send_port = int(sender.ports[-1])
        #Run scan on each port
        for port in self.ports:
            #Make sure you have the correct permissions to run the scan
            try:
                reply = sr1(IP(dst=self.host)/UDP(sport=send_port, dport=int(port)), timeout = 1, verbose=0, retry=3)
            except PermissionError:
                printMessage("ERROR: You do not have the needed permissions to run this scan, try running the script as root", RED)
                return
            if reply:
                verboseMessage(self.host + ":" + port + " is closed", RED)
            else:
                printMessage(self.host + ":" + port + " is open [" + PORT_LOOKUP[int(port)] +"]")

    #Run Christmas Tree Scan on this machine
    def runChristmas(self, sender):
        global PORT_LOOKUP
        send_port = int(sender.ports[-1])
        #Run scan on each port
        for port in self.ports:
            #Make sure you have the correct permissions to run the scan
            try:
                reply = sr1(IP(dst=self.host)/TCP(sport=send_port, dport=int(port), flags="FPU"), timeout = 1, verbose=0)
            except PermissionError:
                printMessage("ERROR: You do not have the needed permissions to run this scan, try running the script as root", RED)
                return

            if reply is None:
                #Port is open|filtered
                printMessage(self.host + ":" + port + " is open|filtered [" + PORT_LOOKUP[int(port)] +"]")
            elif reply.haslayer(TCP):
                if reply.getlayer(TCP).flags == 20:
                    #Port is closed
                    verboseMessage(self.host + ":" + port + " is closed", RED)
                elif reply.haslayer(ICMP):
                    if int(reply.getlayer(ICMP).type) == 3 and int(reply.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                        #Port is filtered
                        printMessage(self.host + ":" + port + " is filtered [" + PORT_LOOKUP[int(port)] +"]")

    #Run traceroute on this machine
    def runTraceroute(self, sender):
        verboseMessage("Performing traceroute on " + self.host)
        for hops in range(1, 30):
            #Make sure you have the correct permissions to run the scan
            try:
                reply = sr1(IP(dst=self.host, ttl=hops)/ICMP(), timeout = 1, verbose=0)
            except PermissionError:
                printMessage("ERROR: You do not have the needed permissions to run this scan, try running the script as root", RED)
                return
            if reply is None:
                break
            elif reply.src == self.host:
                #Reached destination
                if hops == 1:
                    printMessage("1 hop away: " + reply.src + " Done!")
                else:
                    printMessage(str(hops) + " hops away: " + reply.src + " Done!")
                break
            else:
                #Hasn't reached destination yet
                if hops == 1:
                    printMessage("1 hop away: " + reply.src)
                else:
                    printMessage(str(hops) + " hops away: " + reply.src)



class Main(object):
    def __init__(self):
        self.parse_options()
        self.run()
        self.filename = None
    def parse_options(self):
        parser = argparse.ArgumentParser()

        #Create command line arguments
        parser.add_argument("ip_address", nargs="+", type=str, default = "",
                            help="IP address(es) to scan")

        parser.add_argument("-O", "--create-pdf", type=str, dest="create_pdf", default = "",
                            help="Create a pdf with the given output")

        parser.add_argument("-g", "--source-port", type=int, dest="source_port", default = 443,
                            help="Source port")

        parser.add_argument("-S", "--source-address", type=str, dest="source_address", default = "",
                            help="Source address (for spoofing)")

        parser.add_argument("-sn", "--icmp", dest="use_icmp", action="store_true", help="Run ICMP scan (Default if no type is specified)")
        parser.add_argument("-sT", "--tcp", dest="use_tcp", action="store_true", help="Run TCP syn scan")
        parser.add_argument("-sX", "--christmas", dest="use_christmas", action="store_true", help="Run christmas tree scan")
        parser.add_argument("-sU", "--udp", dest="use_udp", action="store_true", help="Run UDP scan")
        parser.add_argument("-T", "--traceroute", dest="traceroute", action="store_true", help="Perform a traceroute")

        parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")

        #Set default values for command line arguments
        parser.set_defaults(use_icmp=False)
        parser.set_defaults(use_tcp=False)
        parser.set_defaults(use_christmas=False)
        parser.set_defaults(use_udp=False)
        parser.set_defaults(traceroute=False)
        parser.set_defaults(traceroute=False)

        args = parser.parse_args()

        #Copy over command line arguments
        self.ip_addresses = args.ip_address
        self.create_pdf = args.create_pdf
        self.source_port = args.source_port
        self.source_address = args.source_address
        self.use_icmp = args.use_icmp
        self.use_tcp = args.use_tcp
        self.use_christmas = args.use_christmas
        self.use_udp = args.use_udp
        self.traceroute = args.traceroute
        self.verbose = args.verbose
        global verboseMessages
        verboseMessages= args.verbose
        

    def parseIP(self, full_address):
        targets = []

        ip_address = full_address.split(":")[0]

        #Parse the mask if there is one
        if "/" in ip_address:
            try:
                mask = int(ip_address.split("/")[1])
                if mask < 0 or mask > 32:
                    printMessage("Error: Invalid mask (" + ip_address + ")", RED)
                    return []
            except ValueError:
                printMessage("Error: Invalid mask (" + ip_address + ")", RED)
                return []
        else:
            mask = 32

        #Parse the ip address
        ip_address_parts = ip_address.split("/")[0].split(".")
        if (len(ip_address_parts) != 4):
            printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
            return []
        try:
            current_ip_addresses = []
            i = -1
            for strpart in ip_address_parts:
                temp_ip_addresses = []
                number_of_addresses = len(current_ip_addresses)
                i = i + 1
                ip_range_comma_parts = strpart.split(",")
                for comma_part in ip_range_comma_parts:
                    # If it has dashes
                    if "-" in comma_part:
                        ip_range_dash_parts = comma_part.split("-")
                        # Bad number of commas
                        if (len(ip_range_dash_parts) != 2):
                                printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
                                return []
                        else:
                            start = int(ip_range_dash_parts[0])
                            end = int(ip_range_dash_parts[1]) + 1
                            if (start > end):
                                printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
                                return []
                            else:
                                for part in range(start, end):
                                    if part < 1 or part > 255:
                                        printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
                                        return []
                                    else:
                                        if part < 1 or part > 255:
                                            printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
                                            return []
                                        else:
                                            #Check if it is the first octet
                                            if i == 0:
                                                temp_ip_addresses.append(part)
                                            else:
                                                for j in range(len(current_ip_addresses)):
                                                    temp_ip_addresses.append((current_ip_addresses[j] << 8) + part)

                    # If it doesn't have any dashes
                    else:
                        part = int(comma_part)
                        if part < 1 or part > 255:
                            printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
                            return []
                        else:
                            #Check if it is the first octet
                            if i == 0:
                                temp_ip_addresses.append(part)
                            else:
                                for j in range(number_of_addresses):
                                    temp_ip_addresses.append((current_ip_addresses[j] << 8) + part)
                current_ip_addresses = temp_ip_addresses

            # Sort and remove duplicates
            temp = []
            for current_ip_address in current_ip_addresses:
                bitmask = (0xFFFFFFFF >> mask) & 0xFFFFFFFF
                for ip in range(current_ip_address & (~bitmask), (current_ip_address | bitmask) + 1):
                    ip_address = "." + str(ip & 255)
                    ip = ip >> 8
                    ip_address = "." + str(ip & 255) + ip_address
                    ip = ip >> 8
                    ip_address = "." + str(ip & 255) + ip_address
                    ip = ip >> 8
                    ip_address = str(ip & 255) + ip_address
                    temp.append(ip_address)
            current_ip_addresses = sorted(set(temp))
                 
        except ValueError:
            printMessage("Error: Invalid IP address (" + ip_address + ")", RED)
            return []


        #Parse the ports
        full_ports = full_address.split(":")[1:]
        ports = []
        try:
            if ":" in full_address:
                for full_port in full_ports:
                    for comma_port in full_port.split(","):
                        if "-" in comma_port:
                            dash_ports = comma_port.split("-")
                            if len(dash_ports) != 2:
                                printMessage("Error: Invalid port (" + ip_address + ")", RED)
                                return []
                            else:
                                start = int(dash_ports[0])
                                end = int(dash_ports[1]) + 1
                                if start >= end:
                                    printMessage("Error: Invalid port (" + ip_address + ")", RED)
                                    return []
                                else:
                                    for j in range(start, end):
                                        if j < 1 or j > 65535:
                                            printMessage("Error: Invalid port (" + ip_address + ")", RED)
                                            return []
                                        ports.append(j)
                        else:
                            if comma_port != "":
                                int_port = int(comma_port)
                                if int_port < 1 or int_port > 65535:
                                    printMessage("Error: Invalid port (" + ip_address + ")", RED)
                                    return []
                                ports.append(int_port)
                            else:
                                printMessage("Error: Invalid port (" + ip_address + ")", RED)
                                return []
            else:
                for port in default_ports:
                    ports.append(port)
        except ValueError:
            printMessage("Error: Invalid port (" + ip_address + ")", RED)
            return []

        temp = sorted(set(ports))
        ports = []
        for port in temp:
            ports.append(str(port))

        for current_ip_address in current_ip_addresses:
            targets.append(Target(current_ip_address, ports))

        return targets


    def run(self):
        #Default to icmp if no type of scan is specified
        if (not (self.use_icmp or self.use_tcp or self.use_udp or self.use_christmas or self.traceroute)):
            self.use_icmp = True
        if (self.create_pdf != ""):
            verboseMessage("Creating was selected (" + self.create_pdf + ")")
            #Make sure pdflatex is installed to generate the pdf
            if os.system("which pdflatex &>/dev/null") == 0:
                global create_pdf
                create_pdf = True
                #Delete any file that may be where the destination pdf is
                os.system("rm -f " + self.create_pdf) 
            else:
                printMessage("Error: pdflatex not found, not generating pdf of output", RED)
                self.create_pdf = ""

            #Add headers to tex file to generate pdf
            os.system("echo \"\documentclass{article}\" > temp.tex") 
            os.system("echo \"\\begin{document}\" >> temp.tex") 

        if (self.source_port != ""):
            verboseMessage("Using port " + str(self.source_port))

        #Set source port
        if (self.source_address != ""):
            verboseMessage("Using address " + self.source_address)
        else:
            self.source_address = "BOGUS" #TODO: Replace with actual ip address

        if (self.use_icmp):
            verboseMessage("Using ICMP")
        if (self.use_tcp):
            verboseMessage("Using TCP")
        if (self.use_udp):
            verboseMessage("Using UDP")
        if (self.use_christmas):
            verboseMessage("Using christmas tree scan")
        if (self.traceroute):
            verboseMessage("Performing a traceroute")

        #Process ip addresses from input
        targets = []
        for ip_address in self.ip_addresses:
            new_targets = self.parseIP(ip_address)
            for target in new_targets:
                targets.append(target)
        if (self.source_address == "BOGUS"):
            source_address = IP().src
        else:
            source_address = self._source_address

        source_port = []
        source_port.append(str(self.source_port))

        source = Target(source_address, source_port)

        verboseMessage("Targets:", BOLD + BLUE)
        for target in targets:
            verboseMessage(target.toString())

        if (self.use_icmp):
            printMessage("[Starting ICMP scans]", BOLD + BLUE)
            for target in targets:
                target.runICMP(source)
        if (self.traceroute):
            printMessage("[Starting Traceroute]", BOLD + BLUE)
            for target in targets:
                target.runTraceroute(source)
        if (self.use_tcp):
            printMessage("[Starting TCP scans]", BOLD + BLUE)
            for target in targets:
                target.runTCP(source)
        if (self.use_udp):
            printMessage("[Starting UDP scans]", BOLD + BLUE)
            for target in targets:
                target.runUDP(source)
        if (self.use_christmas):
            printMessage("[Starting Christmas Tree scan]", BOLD + BLUE)
            for target in targets:
                target.runChristmas(source)
        #Add the footer to the tex file and generate the pdf
        if (self.create_pdf != ""):
            os.system("echo \"\\end{document}\" >> temp.tex") 
            os.system("pdflatex temp.tex &>/dev/null") 
            os.system("mv temp.pdf " + self.create_pdf) 
            os.system("rm temp.tex") 
            os.system("rm temp.aux") 
            os.system("rm temp.log") 


if __name__ == '__main__':
    m = Main()
