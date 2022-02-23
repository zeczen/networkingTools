import ipaddress
import os
import random
import sys
from contextlib import contextmanager

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sr1

DNS_SERVER = '8.8.8.8'
query_id = 0


@contextmanager
def output_disable():
    """
    this function disable outputs
    """
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


def get_port_rand():
    return random.randint(500, 2 ** 16)


def validate_ipv4(address):
    """
    this function check if string 'address' is a valid IPv4 address.
    :param address: string
    :return: bool
    """
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def validate_ipv6(address):
    """
    this function check if string 'address' is a valid IPv6 address.
    :param address: string
    :return: bool
    """
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv6Address)
    except ValueError:
        return False


def validate_mapping_query(arguments):
    """
    this function check if the arguments the program receive is valid mapping arguments (not reverse mapping).
    :param arguments: list of the arguments
    :1yield: bool if args are valid
    :2yield: the URN
    """
    if not len(arguments) == 1:
        # validate that we receive 1 arguments
        yield False
        return

    # no need for special test1
    yield True
    yield arguments[0]  # the URN
    return


def validate_reverse_mapping(arguments):
    """
    this function check if the arguments the program receive is valid reverse mapping arguments.
    :param arguments: list of the arguments
    :1yield: bool if args are valid
    :2yield: the IP
    """
    if not len(arguments) == 2:
        # validate that we receive 2 arguments
        yield False
        return

    if arguments[0] not in ['-type=PTR', '-type=ptr']:
        yield False
        return

    yield True
    yield arguments[-1]  # the IP
    return


def reverse_mapping_scapy(ip):
    global query_id
    query_id += 1

    addr = '.'.join(ip.split('.')[::-1]) + '.in-addr.arpa'
    packet = IP(dst=DNS_SERVER) / UDP(sport=get_port_rand(), dport=53) / DNS(id=query_id, rd=1,
                                                                             qd=DNSQR(qname=addr, qtype=12))
    ans = sr1(packet, timeout=8, verbose=False)
    if ans is not None:
        try:
            return ans[DNSRR].rdata.decode().strip('.')
        except IndexError:
            pass
    return 'Not Found'


def get_addresses(code, msg):
    """
    this function receive message and code and
    return list of all the Resource Records that have type equal to code
    :param msg: DNSRR message
    :param code: the code to filter
    """
    addresses = []
    i = 0

    if msg is not None:

        try:
            while True:
                data = msg[DNS][DNSRR][i].rdata
                if msg[DNS][DNSRR][i].type == code:
                    # if is a type of code
                    addresses.append(data)
                i += 1
        except IndexError:
            pass

    return sorted(addresses)


def get_ip_scapy(address):
    """
    this function get the ip address/s of the URN address parameter using scapy
    :param address: string URN to find hos IP addresses
    :1yield: list of IP v4 addresses
    :2yield: list of IP v6 addresses
    :3yield: list of CNAME/s
    """
    global query_id
    query_id += 1
    packet_v4 = IP(dst=DNS_SERVER) / UDP(sport=get_port_rand(), dport=53) / DNS(id=query_id,
                                                                                qd=DNSQR(qtype=1, qname=address))
    # packet IPv4

    query_id += 1
    packet_v6 = IP(dst=DNS_SERVER) / UDP(sport=get_port_rand(), dport=53) / DNS(id=query_id,
                                                                                qd=DNSQR(qtype=28, qname=address))
    # packet IPv6

    query_id += 1
    packet_CNAME = IP(dst=DNS_SERVER) / UDP(sport=get_port_rand(), dport=53) / DNS(id=query_id,
                                                                                   qd=DNSQR(qtype=5, qname=address))
    # packet CNAME

    # get the IPv4 addresses:
    ans_v4 = sr1(packet_v4, timeout=2, verbose=False)  # if the timeout is finished, ans is NoneType
    addresses_v4 = get_addresses(1, ans_v4)
    yield addresses_v4

    # get the IPv6 addresses:
    ans_v6 = sr1(packet_v6, timeout=2, verbose=False)
    addresses_v6 = get_addresses(28, ans_v6)
    yield addresses_v6

    # get the CNAME IP addresses:
    ans_CNAME = sr1(packet_CNAME, timeout=2, verbose=False)
    address_CNAME = get_addresses(5, ans_CNAME)
    yield list(map(lambda addr: addr.decode().strip('.'), address_CNAME))


def ns_request(query_command_generator):
    urn = next(query_command_generator)
    with output_disable():
        # to disable output - we don't want output from these functions

        addresses_scapy = get_ip_scapy(urn)
        addresses_v4 = next(addresses_scapy)
        addresses_v6 = next(addresses_scapy)
        address_cname = next(addresses_scapy)

    # enable output again

    print()

    if len(addresses_v4) + len(addresses_v6) > 0:
        # if we have one address or more:

        print('Result: ')
    else:
        print('Not found')
    if not len(addresses_v4) == 0:
        print('IPv4:', end='\t')
        print(', '.join(addresses_v4))
    if not len(addresses_v6) == 0:
        print('IPv6:', end='\t')
        print(', '.join(addresses_v6))
    if not len(address_cname) == 0:
        print('CNAME:', end='\t')
        print(', '.join(address_cname))


def ptr_request(reverse_command_generator):
    with output_disable():
        # to disable output - we don't want output from these functions

        ip = next(reverse_command_generator)
        address = reverse_mapping_scapy(ip)
        # enable output again
    print()
    # clearing lines from the console: to have a clean console
    print(address)


def main():
    args = sys.argv[1:]  # the args
    query_command_generator = validate_mapping_query(args)
    reverse_command_generator = validate_reverse_mapping(args)

    valid_query_command = next(query_command_generator)
    valid_reverse_command = next(reverse_command_generator)

    if not valid_query_command and not valid_reverse_command:
        # if the arguments are not valid we finish
        print('Arguments are not valid')
        print('Closing program')
        quit()

    elif valid_query_command:
        ns_request(query_command_generator)

    elif valid_reverse_command:
        ptr_request(reverse_command_generator)


if __name__ == '__main__':
    main()
