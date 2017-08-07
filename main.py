"""
https://github.com/unazed/Packet-Decapsulation/
"""


from pprint import pprint
from re import findall

matlib = True
try:
    import matplotlib.pyplot as plt
except ImportError:
    print("{*} Matplotlib moduled not installed, 'packet' argument will not be supported")
    matlib = False

import socket
import struct
import sys
import time


def recv_all(sockfd, min_recv=512):
    data = ""
    while 1:
        __ = sockfd.recv(min_recv)
        if not __:
            return data
        elif len(__) < min_recv:
            return data + __
        data += __
    return data
    # NOTE: redundant?


def parse_udp(data):
    SRC_PORT = (ord(data[0]) << 8) + ord(data[1])
    DST_PORT = (ord(data[2]) << 8) + ord(data[3])
    LENGTH = (ord(data[4]) << 8) + ord(data[5])
    CHECKSUM = (ord(data[6]) << 8) + ord(data[7])

    return {
        "src port": SRC_PORT,
        "dst port": DST_PORT,
        "length": LENGTH,
        "checksum": CHECKSUM,
        "data": data[8:]
    }


def parse_icmp(data):
    ICMP_TYPE = ord(data[0])
    ICMP_CODE = ord(data[1])
    ICMP_CHKS = (ord(data[2]) << 8) + ord(data[3])
    ICMP_DATA = data[4:]

    return {
        "type": ICMP_TYPE,
        "code": ICMP_CODE,
        "checksum": ICMP_CHKS,
        "data": ICMP_DATA
    }


def parse_tcp(data):
    SRC_PORT = (ord(data[0]) << 8) + ord(data[1])
    DST_PORT = (ord(data[2]) << 8) + ord(data[3])
    SEQ_NUMB = ((((ord(data[4]) << 8) +\
                   ord(data[5]) << 8) +\
                   ord(data[6]) << 8) +\
                   ord(data[7]))
    ACK_NUMB = ((((ord(data[8]) << 8) +\
                   ord(data[9]) << 8) +\
                   ord(data[10]) << 8) +\
                   ord(data[11]))
    DAT_OFFS = ord(data[12]) >> 4
    RESERVED = ord(data[12]) & 0b00001110
    ECN_NNCE = ord(data[12]) & 0b00000001
    CNG_WDWR = ord(data[13]) >> 7
    ECE_ECHO = ord(data[13]) & 0b01000000
    URG_PNTR = ord(data[13]) & 0b00100000
    ACK_FLAG = ord(data[13]) & 0b00010000
    PSH_FUNC = ord(data[13]) & 0b00001000
    RST_CONC = ord(data[13]) & 0b00000100
    SYN_SEQN = ord(data[13]) & 0b00000010
    FIN_PACK = ord(data[13]) & 0b00000001
    WINDOW_SIZE = (ord(data[14]) << 8) + ord(data[15])
    CHECKSUM = (ord(data[16]) << 8) + ord(data[17])
    URG_FIELD = (ord(data[17]) << 8) + ord(data[18])
    # No need for conditionals to check if urgent field is set,
    # Same goes for the Acknowledgement Number field.
    OPTIONS = "\x00" * 4
    if DAT_OFFS > 5:
        OPTIONS = data[20:25]
    return {
        "src port": SRC_PORT,
        "dst port": DST_PORT,
        "window size": WINDOW_SIZE,
        "seq number": SEQ_NUMB,
        "data offset": DAT_OFFS,
        "ack number": ACK_NUMB,
        "reserved": RESERVED,
        "checksum": CHECKSUM,
        "urgent field": URG_FIELD,
        "options": format(option_parser(OPTIONS), 'x'),
        "data": data[(DAT_OFFS*32)/8:],
        "flags": {
            "ECN": ECN_NNCE,
            "CWR": CNG_WDWR,
            "ECE": ECE_ECHO,
            "URG": URG_PNTR,
            "ACK": ACK_FLAG,
            "PSH": PSH_FUNC,
            "RST": RST_CONC,
            "SYN": SYN_SEQN,
            "FIN": FIN_PACK,
        }
    }



def hmac_to_ascii(mac, _format='plain'):
    if len(mac) < 6 or not mac:
        return None
    nmac = 0
    add = ''
    for byte in mac:
        if ord(byte) == 0:
            add += '00'
            # NOTE: rethink life
        else:
            nmac += ord(byte)
        nmac <<= 8
    
    if _format == 'plain':
        return add + format(nmac, 'x')[:-2]
    elif _format == 'three':
        __ = findall("...", add + format(nmac, 'x')[:-2])
        return "{}.{}.{}.{}".format(*__)
    elif _format == "two":
        __ = findall("..", add + format(nmac, 'x')[:-2])
        return "{}:{}:{}:{}:{}:{}".format(*__)



def bip_to_ascii(bip):  # bip boop, bip = BinaryIP
    return "{oct1}.{oct2}.{oct3}.{oct4}".format(oct1=ord(bip[0]),
            oct2=ord(bip[1]),
            oct3=ord(bip[2]),
            oct4=ord(bip[3]))

def option_parser(opts):
    __ = 0
    for byte in opts:
        __ += ord(byte)
        __ <<= 8
    return __
    # NOTE: possibly reconsider variable names here.

assert len(sys.argv) == 2  # Usage: python2 main.py <protocol header to return>

if sys.argv[1] == "-h" or sys.argv[1] == "--help":
    raise SystemExit("Usage: python2 main.py <tcp|udp|icmp|ip|eth>")

try:
    RAW_SOCKET = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(2048))
except socket.error as exc: 
    raise SystemExit("[*] Must be root or be run prefixed with 'sudo'\n{exc}".format(exc=exc))

packets = {}

eth_properties = {
    "broadcast": False,
    "loopback": False,
    "type": "",
    "crc": "",
    "data length": 0,
    "data": "",
    "dst": "",
    "src": ""
}

IP_PROTOCOLS = {
    "17": "udp", 
    '6': "tcp",
    '1': "icmp",
    "eth": "eth",
    "ip": "ip",
    "packet": "packet"
}

assert sys.argv[1].lower() in IP_PROTOCOLS.values()  # Protocol not supported or not found.

if sys.argv[1].lower() == "packet" and not matlib:
    raise SystemExit("{*} Install the Matplotlib module in order to use the 'packet' argument")

ip_properties = {
    "version": "",
    "ihl": "",
    "dscp": "",
    "ecn": "",
    "length": "",
    "ident": "",
    "flags": "",
    "fragment offset": "",
    "ttl": "",
    "protocol": "",
    "checksum": "",
    "src": "",
    "dst": "",
    "options": "",
    "multicast": False,
    "data": ""
}

ctime = time.time()

while 1:
    try:
        RAW_DATA = recv_all(RAW_SOCKET)
    except KeyboardInterrupt:
        if len(packets) == 0 and not matlib:
            print("{*} Nothing to display")
            break
        else:
            plt.bar(range(len(packets)), packets.values(), align="center")
            plt.ylabel("Packet count")
            plt.xlabel("Over n seconds")
            plt.xticks(range(len(packets)), packets.keys())
            plt.show()
            break

    """
    ETHERNET PARSING
    """

    ETH_DST, ETH_SRC, ETH_TYP, ETH_CRC, DATA = struct.unpack("!6s6s2s", RAW_DATA[:14]) + (RAW_DATA[-4:], RAW_DATA[14:-4])
    # NOTE: Python 2 doesn't work like Python 3 would with tuple unpacking :C
    # NOTE: Rethink this possibly or find better methods of doing this.

    if ETH_TYP != "\x08\x00":
        print("{*} Possibly unsupported Ethernet version, outputs may differ.")
    
    eth_properties['type'] = ETH_TYP
    eth_properties['crc'] = ETH_CRC
    eth_properties['broadcast'] = True if hmac_to_ascii(ETH_DST).startswith("f" * 10) else False
    eth_properties['data length'] = len(DATA)
    eth_properties['data'] = DATA
    eth_properties['dst'] = hmac_to_ascii(ETH_DST, _format='two')
    eth_properties['src'] = hmac_to_ascii(ETH_SRC, _format='two')
    eth_properties['loopback'] = True if eth_properties['src'] == "00:00:00:00:00:00" else False

    if sys.argv[1].lower() == "eth":
        pprint(eth_properties)
        continue

    """
    IP HEADER PARSING
    """

    RAW_DATA = RAW_DATA[14:-4]
    ip_properties['version'] = ord(RAW_DATA[0]) >> 4
    if ip_properties['version'] != 4:
        print("{*} IPv6 address, may cause errors.")

    ip_properties['ihl'] = ord(RAW_DATA[0]) & 0xF0
    ip_properties['dscp'] = ord(RAW_DATA[1]) >> 2
    ip_properties['ecn'] = ord(RAW_DATA[1]) & 3 
    ip_properties['length'] = (ord(RAW_DATA[2]) << 8) + ord(RAW_DATA[3])
    ip_properties['ident'] = (ord(RAW_DATA[4]) << 8) + ord(RAW_DATA[5])
    ip_properties['flags'] = bin(ord(RAW_DATA[6]) >> 5)
    # NOTE: could use format(..., 'b') instead for cleaner output.
    ip_properties['fragment offset'] = ((ord(RAW_DATA[6]) & 0b00011111) << 8) + ord(RAW_DATA[7])
    ip_properties['ttl'] = ord(RAW_DATA[8])
    __ = ord(RAW_DATA[9])
    ip_properties['protocol'] = IP_PROTOCOLS[str(__)] if str(__) in IP_PROTOCOLS.keys() else __ 
    ip_properties['checksum'] = (ord(RAW_DATA[9]) << 10) + ord(RAW_DATA[11])
    ip_properties['src'] = bip_to_ascii(RAW_DATA[12:16])
    ip_properties['dst'] = bip_to_ascii(RAW_DATA[16:20])

    try:
        packets[str(int(time.time() - ctime))] = packets[str(int(time.time()-ctime))] + 1
    except KeyError:
        packets[str(int(time.time() - ctime))] = 1

    if ip_properties['dst'].startswith("224"):
        ip_properties['multicast'] = True
    if ip_properties['ihl'] > 5:
        ip_properties['options'] = format(option_parser(RAW_DATA[20:32]), 'x')

    ip_properties['data'] = RAW_DATA[20:]

    if sys.argv[1].lower() == "ip":
        pprint(ip_properties)
        continue
    elif sys.argv[1].lower() == "tcp" and ip_properties['protocol'] == "tcp":
        pprint(parse_tcp(ip_properties['data']))
    elif sys.argv[1].lower() == "udp" and ip_properties['protocol'] == "udp":
        pprint(parse_udp(ip_properties['data']))
    elif sys.argv[1].lower() == "icmp" and ip_properties['protocol'] == "icmp":
        pprint(parse_icmp(ip_properties['data']))
    elif sys.argv[1].lower() == "packet" and matlib:
        pprint(packets)
