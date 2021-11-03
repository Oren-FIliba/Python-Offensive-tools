# Python3-Offensive-Tools
This is a repository for me to display and share some simple python3 offensive tools that I built.

## The Tools:
  
  * Pscan_SSH.py - a port scanner that scan the ports randomly and in random times.
                   its checks if port 22 (SSH) is in the open ports and if it is than
                   the user gets the option to run a Threaded Brute force attack.
       ## Usage:  
       
         `python3 Pscan_SSH.py`   # then you will be prompt for the arguments.
                 
   
  * PasswordSniffer.py - this tool is to be used with a MITM attack. 
                         it searches through the sniffed packet's and
                         searches to see if they contain any credentials.
       ## Usage:  
       
          `python3 PasswordSniffer.py`                  
  
  
  * ArpSpoof.py - as its name suggest, it's an arp spoofer, we use the Scapy library in order to modify
                  the ARP packets in order to poisen the arp table of the router and the target for example,
                  so all the network traffic is coming through ou machine, so we can sniff it and analyze it.
       ## Usage:  
     
           `python3 ArpSpoofer.py <Router IP> <Target IP>`
                  
 
 * hashCrack.py - a very fast and reliable hash cracking tool for MD5, SHA1, SHA256, SHA224, SHA224, SHA512
        
      ## Usage:  
       
            `python3 hashCrack.py <hash type> <wordlist> <target hash>`
  
 * BruteWifi.py - a simple Wifi password brute forcer.  (require a wireless interface)
        
      ## Usage:  
       
            `BruteWifi.py <Wifi name (ssid)> <wordlist>`


# C2_Center
  
  A simple yet effective Command & control framework, to handle multiple connections
  the purpose of this project is to make exploitation, post exploitation and enumaration simple and organized.
  
## Features
  
  `GENERAL:
            quit                                --> Quit Session With The Target
            background                          --> Background The Current Session
            clear                               --> Clear The Screen
            cd *Directory Name*                 --> Changes Directory On Target System
            upload *file name*                  --> Upload File To The target Machine
            screenshot             				      --> Takes a Screenshot Of The Target Machine
            download *file name*                --> Download File From Target Machine
            keylog_start                        --> Start The Keylogger
            keylog_dump                         --> Print Keystrokes That The Target Inputed
            keylog_stop                         --> Stop And Self Destruct Keylogger File
            persistence *RegName* *fileName*    --> Create Persistence In Registry
        
        PRIVESC SCRIPTS:
            linpeas                             --> (LINUX) Uploads linpeas.sh To The Target
            winpeas                             --> (WINDOWS) Upload winpeas.exe To The Target
            seatbelt                            --> Uploads seatbelt.exe to the target.{RED}
        
        DOMAIN ENUM:
            Pview                               --> Uploads PowerView.ps1 To The Target
            bloodhound                          --> Uploads sharphound.ps1 To The Target`
            
  ## Usage
    - Run the Command & control server -
    `python3 C2_Center.py <Local IP adress> <PORT>` - now the server is running and will display a message everytime he got a connection.
    - Type `?` for help menu
    
    - (FOR LINUX) - Get the `backdoor.py` script onto the linux machine and run it. 
    
    - (FOR WINDOWS) - Get the `backdoor.exe` onto the windows machine (can also be done via phishing with a SFX paylod) and run it.
    
    ### Once you have multiple sessions you can see them with the `targets` command and interact with each session with the command:
        `session <session ID>`
    ### Type '?' to see the commands and features that are avalible.
    
  ### The project is still in working progress and will hopefully update every so often.
   
   
