import socket
import struct
import textwrap
import binascii
import sys

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    filters = {"ICMP": 1, "UDP": 17, "TCP": 6}
    filter_protocol = None

    if len(sys.argv) == 2:
        filter_input = sys.argv[1].upper()
        if filter_input in filters:
            filter_protocol = filters[filter_input]
            print(f"Filter applied: {filter_input}")
        else:
            print(f"Invalid filter: {filter_input}. Sniffing all protocols.")

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 'IPV6':
            new_packet, next_proto = ipv6_header(data)
            print_packets_v6(filter_protocol, next_proto, new_packet)

        elif eth_proto == 'IPV4':
            print_packets_v4(filter_protocol, data, raw_data)


def print_packets_v4(filter_protocol, data, raw_data):
    version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

    # ICMP
    if proto == 1 and (filter_protocol is None or filter_protocol == 1):
        icmp_type, code, checksum, data = icmp_packet(data)
        print("*******************ICMP***********************")
        print(f"\tICMP Type: {icmp_type}")
        print(f"\tICMP Code: {code}")
        print(f"\tICMP Checksum: {checksum}")

    # TCP
    elif proto == 6 and (filter_protocol is None or filter_protocol == 6):
        src_port, dest_port, sequence, acknowledgment, flags, data = tcp_seg(data)
        flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = flags
        print("*******************TCPv4***********************")
        print(f"Version: {version}\nHeader Length: {header_length}\nTTL: {ttl}")
        print(f"Protocol: {proto}\nSource: {src}\nTarget: {target}")
        print('*****TCP Segment*****')
        print(f'Source Port: {src_port}\nDestination Port: {dest_port}')
        print(f'Sequence: {sequence}\nAcknowledgment: {acknowledgment}')
        print('*****Flags*****')
        print(f'URG: {flag_urg}\nACK: {flag_ack}\nPSH: {flag_psh}')
        print(f'RST: {flag_rst}\nSYN: {flag_syn}\nFIN: {flag_fin}')

        if len(data) > 0:
            print('*****TCP Data*****')
            print(format_output_line("", data))

    # UDP
    elif proto == 17 and (filter_protocol is None or filter_protocol == 17):
        src_port, dest_port, length, data = udp_seg(data)
        print("*******************UDPv4***********************")
        print(f"Version: {version}\nHeader Length: {header_length}\nTTL: {ttl}")
        print(f"Protocol: {proto}\nSource: {src}\nTarget: {target}")
        print('*****UDP Segment*****')
        print(f'Source Port: {src_port}\nDestination Port: {dest_port}\nLength: {length}')


def print_packets_v6(filter_protocol, next_proto, new_packet):
    remaining_packet = ""

    if next_proto == 'ICMPv6' and (filter_protocol is None or filter_protocol == 1):
        remaining_packet = icmpv6_header(new_packet)
    elif next_proto == 'TCP' and (filter_protocol is None or filter_protocol == 6):
        remaining_packet = tcp_header(new_packet)
    elif next_proto == 'UDP' and (filter_protocol is None or filter_protocol == 17):
        remaining_packet = udp_header(new_packet)

    return remaining_packet


def tcp_header(new_packet):
    packet = struct.unpack("!2H2I4H", new_packet[:20])
    src_port = packet[0]
    dst_port = packet[1]
    seq_num = packet[2]
    ack_num = packet[3]
    data_offset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    flags = packet[4] & 0x003F
    urg_flag = flags & 0x20
    ack_flag = flags & 0x10
    psh_flag = flags & 0x08
    rst_flag = flags & 0x04
    syn_flag = flags & 0x02
    fin_flag = flags & 0x01
    window = packet[5]
    checksum = packet[6]
    urg_ptr = packet[7]

    print("*******************TCP***********************")
    print(f"\tSource Port: {src_port}")
    print(f"\tDestination Port: {dst_port}")
    print(f"\tSequence Number: {seq_num}")
    print(f"\tAck Number: {ack_num}")
    print(f"\tData Offset: {data_offset}")
    print(f"\tReserved: {reserved}")
    print(f"\tTCP Flags: {flags}")

    if urg_flag:
        print("\tUrgent Flag: Set")
    if ack_flag:
        print("\tAck Flag: Set")
    if psh_flag:
        print("\tPush Flag: Set")
    if rst_flag:
        print("\tReset Flag: Set")
    if syn_flag:
        print("\tSyn Flag: Set")
    if fin_flag:
        print("\tFin Flag: Set")

    print(f"\tWindow: {window}")
    print(f"\tChecksum: {checksum}")
    print(f"\tUrgent Pointer: {urg_ptr}")
    print(" ")

    return new_packet[20:]


def udp_header(new_packet):
    packet = struct.unpack("!4H", new_packet[:8])
    src_port = packet[0]
    dst_port = packet[1]
    length = packet[2]
    checksum = packet[3]

    print("*******************UDP***********************")
    print(f"\tSource Port: {src_port}")
    print(f"\tDestination Port: {dst_port}")
    print(f"\tLength: {length}")
    print(f"\tChecksum: {checksum}")
    print(" ")

    return new_packet[8:]


def icmpv6_header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_checksum = struct.unpack(">BBH", data[:4])

    print("*******************ICMPv6***********************")
    print(f"\tICMPv6 Type: {ipv6_icmp_type}")
    print(f"\tICMPv6 Code: {ipv6_icmp_code}")
    print(f"\tICMPv6 Checksum: {ipv6_icmp_checksum}")

    return data[4:]


def next_header(ipv6_next_header):
    header_map = {
        6: 'TCP',
        17: 'UDP',
        43: 'Routing',
        1: 'ICMP',
        58: 'ICMPv6',
        44: 'Fragment',
        0: 'HOPOPT',
        60: 'Destination',
        51: 'Authentication',
        50: 'Encapsulating'
    }

    return header_map.get(ipv6_next_header, 'Unknown')


def ipv6_header(data):
    ipv6_first_word, ipv6_payload_length, ipv6_next_header, ipv6_hoplimit = struct.unpack(">IHBB", data[:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    version = ipv6_first_word >> 28
    traffic_class = (ipv6_first_word >> 20) & 0xFF
    flow_label = ipv6_first_word & 0xFFFFF

    ipv6_next_header = next_header(ipv6_next_header)
    return data[40:], ipv6_next_header


def ethernet_frame(data):
    proto = ""
    eth_header = struct.unpack("!6s6sH", data[:14])
    dst_mac = get_mac_addr(eth_header[0])
    src_mac = get_mac_addr(eth_header[1])
    proto_type = eth_header[2]

    if proto_type == 0x0800:
        proto = 'IPV4'
    elif proto_type == 0x86DD:
        proto = 'IPV6'

    return dst_mac, src_mac, proto, data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return ".".join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_seg(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, (flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin), data[offset:]


def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def format_output_line(prefix, string):
    return '\n'.join([prefix + line for line in textwrap.wrap(string, 80)])
    

main()
