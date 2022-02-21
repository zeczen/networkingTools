import ipaddress
import subprocess
from datetime import datetime
from multiprocessing import Process
from random import randint
from struct import unpack
from time import sleep

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff, sendp

# Constants
OUTPUT_FILE = r"ipscanning.txt"

# Global variables
hosts = []  # the list of the hosts
arp_packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP()


def random_ip(network):
    """
    Generate random host ip in [network]

    :param network: the network to generate the random host from
    :return: the random ip address
    :rtype: str
    """

    network = ipaddress.IPv4Network(network)
    network_int, = unpack("!I", network.network_address.packed)
    # make network address into an integer

    rand_bits = network.max_prefixlen - network.prefixlen
    # calculate the needed bits for the host part

    rand_host_int = randint(0, 2 ** rand_bits - 1)
    # generate random host part

    ip_address = ipaddress.IPv4Address(network_int + rand_host_int)
    # combine the parts

    return ip_address.exploded


def received_arp(packet):
    """
    Handle the arp replay,
    print the host and writing him to the file

    :param packet: the received arp replay packet
    """
    ip_address = packet[ARP].psrc
    mac_address = packet[ARP].hwsrc
    host = (ip_address, mac_address)

    if host in hosts:
        return  # we found him already

    # else

    hosts.append(host)
    print(host, len(hosts))

    with open(OUTPUT_FILE, 'a') as outfile:
        # write the host to the file
        outfile.write(f"\n - {len(hosts)}: IPv4 Address- {host[0]}".ljust(38) +
                      f"MAC Address- {host[1]}")


def listen_arp():
    """
    Listening to the arp replay packets
    """
    sniff(
        lfilter=lambda packet: ARP in packet and packet[ARP].op == 2,
        # prn=lambda p: threading.Thread(target=received_arp, args=(p,)).start(),
        prn=received_arp,
    )


def send_arp(network):
    """
    Send all the arp requests

    :param network: object of type ipaddress.IPv4Network, the current network
    """
    for host in network.hosts():
        arp_packet[ARP].pdst = str(host)
        sendp(arp_packet, verbose=0)


def write_header(network):
    """
    Write the header of the file in 2 steps,
    the first when we start the scanning and the second when we finish

    :param network: [network ip]/[network mask]
    """
    start = datetime.now()

    # creating the file
    with open(OUTPUT_FILE, 'w') as text_file:
        text_file.write(
            f"""
SCANNING:
 - Network:\t{network}
 - Start:\t{start}
 - Finish:\t     
 - Running time:\t   

Hosts:      
"""
        )
    yield None

    finish = datetime.now()
    running_time = finish - start

    text_file = open(OUTPUT_FILE, "r")
    lines = text_file.readlines()
    lines[4] = f' - Finish:\t{finish}\n'
    lines[5] = f' - Running time:\t{running_time}\n'

    text_file = open(OUTPUT_FILE, "w")
    text_file.writelines(lines)
    text_file.close()
    yield None


def ip_scanning(network_specification):
    """
    Send ping (arp request) to every possible ip in the network,
    write the hosts to the [OUTPUT_FILE]

    :param network_specification: the network ip including the mask
    """

    network = ipaddress.IPv4Network(network_specification, False)
    arp_packet[ARP].psrc = random_ip(network)
    # we send packets with a random ip

    t = Process(target=listen_arp)
    t.start()  # run the sniffer

    header_generator = write_header(network)
    next(header_generator)

    sleep(2)
    # give time for the sniff to start before sending the pings

    send_arp(network)  # send the arp request while sniffing

    next(header_generator)

    sleep(0.1)
    # give time for all the last packet to arrive before killing the thread

    t.terminate()  # stop sniffing


def get_network_specification():
    """
    Generate the network ip including the mask using the command line

    :return: [network ip]/[network mask]
    :rtype: str
    """

    ip = get_if_addr(conf.iface)  # the current host ip
    try:
        # for linux
        with subprocess.Popen('ifconfig', stdout=subprocess.PIPE) as proc:
            for _ in range(30):
                line = proc.stdout.readline()
                if ip.encode() in line:
                    mask = list(filter(lambda x: x != b'',
                                       line.rstrip().split(b'netmask')[1].split(b' '))
                                )[0].decode()
                    break
            proc.kill()

    except FileNotFoundError:
        # for windows
        with subprocess.Popen('ipconfig', stdout=subprocess.PIPE) as proc:
            for _ in range(30):
                line = proc.stdout.readline()
                if ip.encode() in line:
                    break
            mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ', b'').decode()
            proc.kill()

    network = str(ipaddress.IPv4Network(f'{ip}/{mask}', False))
    return network


def main():
    try:
        specification = get_network_specification()
    except ipaddress.NetmaskValueError:
        print('You must to connect to the network first')
        return

    ip_scanning(specification)


if __name__ == "__main__":
    main()
