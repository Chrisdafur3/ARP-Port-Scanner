from src.lan_and_port_scanner import Network_Scanner
import argparse
from src import textcolor as tc
from src import logo
import os
import sys
import signal
is_windows = False
try:
    import gnureadline
except:
    is_windows = True
    import pyreadline 



def printlogo():
    tc.printout(logo.ascii_art, tc.GREEN)
    tc.printout("\nDeveloped by Christopher Berry\n\n", tc.GREEN)
    tc.printout("Type 'show' to show all allowed commands\n", tc.CYAN)
    tc.printout("Type 'FILE -y' to save results to a file in the designated output folder (default is disabled)'\n",tc.CYAN)
    tc.printout("Type 'clear' to clear terminal\n", tc.CYAN)

def cmdlist():
    print('\n')
    tc.printout("FILE -y/n\t", tc.BLUE)
    print("Enable/disable output in a .txt file'")
    tc.printout("arpscan\t\t", tc.BLUE)
    print("Search for all devices on your network: Active IP must be a range eg, 192.168.0.0/24 ")
    tc.printout("portscan\t", tc.BLUE)
    print("Search for open ports on a/your network: Active IP must be an individual IP eg, 192.168.0.105")
    tc.printout("show_ip\t\t", tc.BLUE)
    print("Show current active ip")
    tc.printout("rm_range\t", tc.BLUE)
    print("Remove the current active range")
    tc.printout("ch_range\t", tc.BLUE)
    print("Change the current port range")
    tc.printout("show_range\t", tc.BLUE)
    print("Show the current active port range")
    tc.printout("rm_list\t\t", tc.BLUE)
    print("Remove the current port list")
    tc.printout("ch_list\t\t", tc.BLUE)
    print("Change the current port list")
    tc.printout("show_list\t", tc.BLUE)
    print("Show the current port list")
    tc.printout("ch_ip\t\t", tc.BLUE)
    print("Set a new IP or IP range")
    print('\n')


def signal_handler(sig, frame):
    tc.printout("\nGoodbye!\n", tc.RED)
    sys.exit(0)

def completer(text, state):
    options = [i for i in commands if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None

def _quit():
    tc.printout("Goodbye!\n", tc.RED)
    sys.exit(0)

printlogo()
parser = argparse.ArgumentParser(description='Basic Network Scanner Project')
parser.add_argument('ip', type=str, help='add an ip address')
parser.add_argument('-f', '--file', help='save output in a file', action='store_true')
parser.add_argument('-pl', help='Add a list of ports eg 80,443,135')
parser.add_argument('-portscan', help='Scan for open ports in an IP address', action='store_true')
parser.add_argument('-arpscan', help='Scan devices in an IP range', action='store_true')
parser.add_argument('-pr', help='Add a port range eg. 80-110')
args = parser.parse_args()
api = Network_Scanner(args.ip, args.file)

if args.pr:
    pr = (args.pr).split("-")
    port_min = int(pr[0])
    port_max = int(pr[1])
    api.port_min = port_min
    api.port_max = port_max
    api.p_min(port_min)
    api.p_max(port_max)

if args.pl:
    pl = (args.pl).split(',') or (args.pl).split(';')
    api.ports += pl

def _clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    printlogo()
    api.__printIPBanner__()
    api.__showrange__()
    api.__showlist__()

    
commands = {
    'cls':              _clear,
    'clear':            _clear,
    'show':             cmdlist,
    'list':             cmdlist,
    'ls':               cmdlist,   
    'help':             cmdlist,
    'quit':             _quit,
    'exit':             _quit,
    'show_ip':          api.__printIPBanner__,
    'rm_range':         api.rm_range,
    'ch_range':         api.change_range,
    'show_range':       api.__showrange__,
    'rm_list':          api.rm_list,
    'ch_list':          api.change_list,
    'show_list':        api.__showlist__,
    'arpscan':          api.lanScan,
    'portscan':         api.portScan,
    'ch_ip':            api.change_ip
}

signal.signal(signal.SIGINT, signal_handler)
if is_windows:
    pyreadline.Readline().parse_and_bind("tab: complete")
    pyreadline.Readline().set_completer(completer)
else:
    gnureadline.parse_and_bind("tab: complete")
    gnureadline.set_completer(completer)

api.__showrange__()
api.__showlist__()

if args.portscan == True:
    api.portScan()

if args.arpscan == True:
    api.lanScan()
    
while True:
    tc.printout("\nEnter a command: ", tc.GREEN)
    cmd = input()
    _cmd = commands.get(cmd)
    
    if _cmd:
        _cmd()    
    elif cmd == "FILE -y" or cmd == "file -y" or cmd == "FILE -Y" or cmd == "file -Y" or cmd == "File -y":
        api.set_write_file(True)
    elif cmd == "FILE -n" or cmd == "file -y" or cmd == "FILE -N" or cmd == "file -N" or cmd == "File -n":
        api.set_write_file(False)
    elif cmd == "":
        print("")
    else:
        tc.printout("Unknown command\n", tc.RED)