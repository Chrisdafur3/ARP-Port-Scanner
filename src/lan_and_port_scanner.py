import re
import sys
import ipaddress
from scapy.all import *
from src import textcolor as tc
import os.path

class Network_Scanner:
    writeFile = False
    ip_address = ""
    port_min = None
    port_max = None
    ports = []
    search = None

    def __init__(self, ip_address, is_file):
        tc.printout("\nAttempting to fetch IP addresses...", tc.GREEN)
        self.setIP(ip_address)
        self.writeFile = is_file

    def p_min(self, min):
        self.port_min = min
        return self.port_min

    def p_max(self, max):
        self.port_max = max
        return self.port_max

    def setIP(self, ip_address):
        self.ip_address = ip_address
        self.__printIPBanner__()
    
    def change_ip(self):
        tc.printout("Insert new IP address: ", tc.CYAN)
        line = input()
        self.setIP(line)
        tc.printout('\nIP has successfully been changed', tc.GREEN)
        print('\n')
        return

    def change_list(self):
        self.ports.clear()
        tc.printout('insert a new list of ports in format: <int>,<int>,<int> ', tc.CYAN)
        line = input()
        pl = line.split(',') or line.split(';')
        self.ports += pl
        if line == str('REMOVE') or line == 0:
            self.ports.clear()
        tc.printout('Port list has successfully been changed', tc.GREEN)
        print('\n')
        return self.ports

    def rm_list(self):
        if self.ports == []:
            tc.printout('Port list has already been reset', tc.RED)
            print('\n')
        else:
            self.ports.clear()
            tc.printout('List reset successfully', tc.GREEN)
            print('\n')
        return self.ports
    
    def change_range(self):
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
        tc.printout("insert a new port range in format: <int>-<int> ", tc.CYAN)
        line = input()
        port_range_valid = port_range_pattern.search(line.replace(" ",""))
        if port_range_valid:
            self.port_min = int(port_range_valid.group(1))
            self.port_max = int(port_range_valid.group(2))
            if self.port_min == 0 and self.port_max == 0:
                self.port_min = None
                self.port_max = None
            tc.printout('\nPort range changed successfully!', tc.GREEN)
            print('\n')
        else:
            if line == None or line == 0 or line == str('REMOVE'):
                self.port_min = None
                self.port_max = None
                tc.printout('Port range removed', tc.GREEN)
                print('\n')
            else:
                tc.printout('An error has occured!', tc.RED)
                return
        return self.port_min, self.port_max
    
    def rm_range(self):
        if self.port_min == None and self.port_max == None:
            tc.printout('Port Range has already been reset', tc.RED)
            print('\n')
        else:
            self.port_min = None
            self.port_max = None
            tc.printout('Range reset successfully', tc.GREEN)
            print('\n')
        return self.port_min, self.port_max

    def __printIPBanner__(self):
        tc.printout("\nActive IP: ", tc.RED)
        tc.printout(str(self.ip_address), tc.YELLOW)

    def __showrange__(self):
        if self.port_min == None and self.port_max == None:
            tc.printout("\nActive port range: ", tc.RED)
            tc.printout(str('Inactive'), tc.YELLOW)
        else:
            port_range = str(f"{self.port_min}-{self.port_max}")
            tc.printout("\nActive port range: ", tc.RED)
            tc.printout(str(port_range), tc.YELLOW)

    def __showlist__(self):
        if self.ports == []:
            tc.printout('\nActive port list: ', tc.RED)
            tc.printout(str('Inactive'), tc.YELLOW)
            print('\n')
        else:
            tc.printout('\nActive port list: ', tc.RED)
            for x in self.ports:
                tc.printout(x + " ", tc.YELLOW)
            print('\n')

    def lanScan(self):
        ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
        ip_add_range = self.ip_address
        if ip_add_range_pattern.search(ip_add_range):
            tc.printout(f"\n{ip_add_range} is a valid ip address range", tc.GREEN)
            tc.printout("\n")
        else:
            tc.printout(f"\n{ip_add_range} is not a valid ip range", tc.RED)
            tc.printout("\nPlease enter a valid ip range in format: 192.168.0.0/24", tc.CYAN)
            tc.printout("\nPlease Enter a valid IP range: ", tc.CYAN)
            ip_add_range = input()
            self.ip_address = ip_add_range
            tc.printout("\n")

        tc.printout("\nActive IP: ", tc.RED)
        tc.printout(str(self.ip_address), tc.YELLOW)
        print('\n')

        tc.printout('\n[*] Scanning...\n', tc.MAGENTA)

        arp_list = scapy.all.arping(ip_add_range)

        tc.printout('\n[*] Scan Complete!', tc.MAGENTA)

        if self.writeFile:
            tc.printout("\nFile name will be saved as '<file>_portScan.txt'", tc.CYAN)
            tc.printout("\nEnter a File name: ", tc.CYAN)
            name_file = input()
            file_name = "lanscan/"+ name_file + "_lanScan.txt"
            sys.stdout = open(file_name, "w")
            arp_list = scapy.arping(ip_add_range)
            sys.stdout.close()
            sys.stdout = sys.__stdout__
            tc.printout("\nFile Saved successfully", tc.GREEN)
            print('\n')
        
        return

    def portScan(self):
        conf.verb=0
        conf.nofilter=1
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
        src_port = RandShort()
        port_min = self.port_min
        search = None
        port_max = self.port_max
        open_ports = []
        ip_add_entered = self.ip_address
        while True:
            try:
                ip_address_obj = ipaddress.ip_address(ip_add_entered)
                tc.printout("\nYou have entered a valid ip address", tc.GREEN)
                if self.ports == [] and self.port_min == None:
                    tc.printout('\nWould you like to search specific ports or a port range? pl/pr ', tc.GREEN)
                    search = input()
                break
                
            except:
                tc.printout("\nYou have entered an invalid ip address", tc.RED)
                tc.printout("\nPlease Enter a valid ip address in format: 192.168.0.1", tc.CYAN)
                tc.printout("\nPlease enter a valid ip address: ", tc.CYAN)
                ip_add_entered = input()
                ip_address_obj = ipaddress.ip_address(ip_add_entered)
                self.ip_address = ip_add_entered
                tc.printout("\nYou have entered a valid ip address", tc.GREEN)
                if self.ports == [] and self.port_min == None:
                    tc.printout('\nWould you like to search specific ports or a port range? pl/pr ', tc.GREEN)
                    search = input()
                break
        if self.ports != [] and self.port_min != None and self.port_max != None:
            try:
                tc.printout("\nActive IP: ", tc.RED)
                tc.printout(str(self.ip_address), tc.YELLOW)
                self.__showrange__()
                self.__showlist__()

                if self.ports == []:
                    tc.printout("\nPlease enter the list of ports you want to scan in format: <int>,<int>,<int> (ex would be 80,135,443)", tc.CYAN)
                    tc.printout("\nEnter a list of ports: ", tc.CYAN)
                    port_list = input()
                    pl = port_list.split(',')
                    self.ports += pl
                tc.printout('\n[*] Scanning...', tc.MAGENTA)
                try:
                    for port in self.ports:
                        stealth_scan_resp = sr1(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=int(port) ,flags="S"),timeout=10)
                        if(str(type(stealth_scan_resp))=="<type ‘NoneType’>"):
                            prt = str(f"Port {int(port)} is filtered")
                        elif(stealth_scan_resp.haslayer(TCP)):
                            if(stealth_scan_resp.getlayer(TCP).flags == str('SA')):
                                send_rst = sr(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=int(port),flags="R"),timeout=10)
                                prt = str(f"Port {int(port)} is Open")
                            elif (stealth_scan_resp.getlayer(TCP).flags == str('RA')):
                                prt = str(f"Port {int(port)} is Closed")
                            elif(stealth_scan_resp.haslayer(ICMP)):
                                if(int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                    prt = str(f"Port {int(port)} is filtered")
                        if prt == f"Port {int(port)} is Open":
                            tc.printout(f"\nPort {int(port)} is Open", tc.GREEN)
                            open_ports.append(prt)
                        elif prt == f"Port {int(port)} is filtered":
                            tc.printout(f'\nPort {int(port)} is filtered', tc.YELLOW)
                        elif prt == f'Port {int(port)} is Closed':
                            tc.printout(f'\nPort {int(port)} is Closed', tc.RED)

                    for port in range(port_min, port_max + 1):
                        stealth_scan_resp = sr1(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=port ,flags="S"),timeout=10)
                        if(str(type(stealth_scan_resp))=="<type ‘NoneType’>"):
                            prt = str(f"Port {port} is filtered")
                        elif(stealth_scan_resp.haslayer(TCP)):
                            if(stealth_scan_resp.getlayer(TCP).flags == str('SA')):
                                send_rst = sr(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=port,flags="R"),timeout=10)
                                prt = str(f"Port {port} is Open")
                            elif (stealth_scan_resp.getlayer(TCP).flags == str('RA')):
                                prt = str(f"Port {port} is Closed")
                            elif(stealth_scan_resp.haslayer(ICMP)):
                                if(int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                    prt = str(f"Port {port} is filtered")
                        if prt == f"Port {int(port)} is Open":
                            tc.printout(f"\nPort {int(port)} is Open", tc.GREEN)
                            open_ports.append(prt)
                        elif prt == f"Port {int(port)} is filtered":
                            tc.printout(f'\nPort {int(port)} is filtered', tc.YELLOW)
                        elif prt == f'Port {int(port)} is Closed':
                            tc.printout(f'\nPort {int(port)} is Closed', tc.RED)
                except:
                    tc.printout("\nAn error has occured!", tc.RED)
                tc.printout('\n[*] Scan Complete!', tc.MAGENTA)
            except:
                pass

        elif search == str('pr') or search == str('PR') or search == str('Pr') or self.port_min != None and self.port_max != None:
            if self.port_min == None and self.port_max == None:
                tc.printout("\nPlease enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)", tc.CYAN)
                tc.printout("\nEnter a port range: ", tc.CYAN)
                port_range = input()
                port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
                if port_range_valid:
                    port_min = int(port_range_valid.group(1))
                    port_max = int(port_range_valid.group(2))
                    
            else:
                port_min = self.port_min
                port_max = self.port_max
                
            tc.printout("\nActive IP: ", tc.RED)
            tc.printout(str(self.ip_address), tc.YELLOW)
            self.__showrange__()
            self.__showlist__()
            tc.printout('\n[*] Scanning...', tc.MAGENTA)
            print('\n')
            try:
                for port in range(port_min, port_max + 1):
                    stealth_scan_resp = sr1(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=port ,flags="S"),timeout=10)
                    if(str(type(stealth_scan_resp))=="<type ‘NoneType’>"):
                        prt = str(f"Port {port} is filtered")
                    elif(stealth_scan_resp.haslayer(TCP)):
                        if(stealth_scan_resp.getlayer(TCP).flags == str('SA')):
                            send_rst = sr(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=port,flags="R"),timeout=10)
                            prt = str(f"Port {port} is Open")
                        elif (stealth_scan_resp.getlayer(TCP).flags == str('RA')):
                            prt = str(f"Port {port} is Closed")
                        elif(stealth_scan_resp.haslayer(ICMP)):
                            if(int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                prt = str(f"Port {port} is filtered")
                    if prt == f"Port {int(port)} is Open":
                        tc.printout(f"\nPort {int(port)} is Open", tc.GREEN)
                        open_ports.append(prt)
                    elif prt == f"Port {int(port)} is filtered":
                        tc.printout(f'\nPort {int(port)} is filtered', tc.YELLOW)
                    elif prt == f'Port {int(port)} is Closed':
                        tc.printout(f'\nPort {int(port)} is Closed', tc.RED)
            except:
                pass
            print('\n')
            tc.printout('\n[*] Scan Complete!', tc.MAGENTA)
            print('\n')
        elif search == str('pl') or search == str('PL') or search == str('Pl') or self.ports != []:
            try:
                if self.ports == []:
                    tc.printout("\nPlease enter the list of ports you want to scan in format: <int>,<int>,<int> (ex would be 80,135,443)", tc.CYAN)
                    tc.printout("\nEnter a list of ports: ", tc.CYAN)
                    port_list = input()
                    pl = port_list.split(',')
                    self.ports += pl
                tc.printout("\nActive IP: ", tc.RED)
                tc.printout(str(self.ip_address), tc.YELLOW)
                self.__showrange__()
                self.__showlist__()
                tc.printout('\n[*] Scanning...', tc.MAGENTA)
                for port in self.ports:
                    try:
                        stealth_scan_resp = sr1(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=int(port) ,flags="S"),timeout=10)
                        if(str(type(stealth_scan_resp))=="<type ‘NoneType’>"):
                            prt = str(f"Port {int(port)} is filtered")
                        elif(stealth_scan_resp.haslayer(TCP)):
                            if(stealth_scan_resp.getlayer(TCP).flags == str('SA')):
                                send_rst = sr(IP(dst=ip_add_entered)/TCP(sport=src_port,dport=int(port),flags="R"),timeout=10)
                                prt = str(f"Port {int(port)} is Open")
                            elif (stealth_scan_resp.getlayer(TCP).flags == str('RA')):
                                prt = str(f"Port {int(port)} is Closed")
                            elif(stealth_scan_resp.haslayer(ICMP)):
                                if(int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                    prt = str(f"Port {int(port)} is filtered")
                        if prt == f"Port {int(port)} is Open":
                            tc.printout(f"\nPort {int(port)} is Open", tc.GREEN)
                            open_ports.append(prt)
                        elif prt == f"Port {int(port)} is filtered":
                            tc.printout(f'\nPort {int(port)} is filtered', tc.YELLOW)
                        elif prt == f'Port {int(port)} is Closed':
                            tc.printout(f'\nPort {int(port)} is Closed', tc.RED)
                    except:
                        pass
                print('\n')
                tc.printout('\n[*] Scan Complete!', tc.MAGENTA)
            except:
                tc.printout('Oops! Something went wrong', tc.RED)
                return

        if self.writeFile:
            file_name = "portscan/" + self.ip_address + "_portScan.txt"
            if os.path.exists(file_name):
                with open(file_name, 'a') as f:
                    for x in open_ports:
                        f.write(str(x) + '\n')
                        tc.printout('\nFile was appeneded to Successfully!',tc.GREEN)
                        f.close()
                        print('\n')
            else:
                with open(file_name, "w") as f:
                    for x in open_ports:
                        f.write(str(x) + "\n")
                    tc.printout("\nFile Saved Successfully!", tc.GREEN)
                    f.close()
                    print('\n')
        return

    def set_write_file(self, flag):
        if flag:
            tc.printout("Write to file: ")
            tc.printout("enabled", tc.GREEN)
            tc.printout("\n")
        else:
            tc.printout("Write to file: ")
            tc.printout("disabled", tc.RED)
            tc.printout("\n")

        self.writeFile = flag