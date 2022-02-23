import sys
from time import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def tracert(dst):
    p = IP(dst=dst) / ICMP(seq=1, id=1)
    finish = False
    i = 1

    print()
    while not finish:
        print(str(i).ljust(5), end=' ')

        p[IP].ttl = i

        a = time()
        ans = sr1(p, timeout=3, verbose=False)
        b = time()

        if ans is not None:
            print(ans[IP].src.ljust(15), end='\t')
            print('RTT ', str(round((b - a) * (10 ** 3), 3)) + 'ms')
            finish = ans[ICMP].type == 0
        else:
            print("Unknown".ljust(15), "\tTimeout")

        i += 1
    print('\nTrace complete.')


def main():
    try:
        tracert(sys.argv[1])
    except OSError:
        print(
            'illegal arguments, or no connection'
        )


if __name__ == "__main__":
    main()
