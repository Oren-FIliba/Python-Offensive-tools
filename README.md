# Python3-Offensive-Tools
This is a repository for me to display and share some simple python3 offensive tools that I built.

## The Tools:
  
  * Pscan_SSH.py - a port scanner that scan the ports randomly and in random times.
                   its checks if port 22 (SSH) is in the open ports and if it is than
                   the user gets the option to run a Threaded Brute force attack.
   
  * PasswordSniffer.py - this tool is to be used with a MITM attack. 
                         it searches through the sniffed packet's and
                         searches to see if they contain any credentials.
                         
  
  * ArpSpoof.py - as its name suggest, it's an arp spoofer, we use the Scapy library in order to modify
                  the ARP packets in order to poisen the arp table of the router and the target for example,
                  so all the network traffic is coming through ou machine, so we can sniff it and analyze it.
                  
  * hashCrack.py - a very fast and reliable hash cracking tool for MD5, SHA1, SHA256, SHA224, SHA224, SHA512
         ### Usage:  
              `python3 hashCrack.py <hash type> <wordlist> <target hash>`
