"""IPv4 raw-socket packet sniffer for authorized network diagnostics.

Windows: run as Administrator (captures IPv4 traffic supported by Winsock).
Linux: run with sudo/root (IPPROTO_TCP raw sockets capture TCP only).
"""
import argparse
import socket
import struct
from collections import Counter
from datetime import datetime


def parse_ipv4(data):
    if len(data) < 20:
        return None
    version_ihl = data[0]
    version, ihl = version_ihl >> 4, (version_ihl & 15) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return None
    total_length = struct.unpack('!H', data[2:4])[0]
    if total_length < ihl:
        return None
    protocol = data[9]
    source = socket.inet_ntoa(data[12:16])
    destination = socket.inet_ntoa(data[16:20])
    fragment = struct.unpack('!H', data[6:8])[0]
    offset = fragment & 0x1FFF
    return source, destination, protocol, ihl, min(total_length, len(data)), offset


def decode_packet(data):
    ip = parse_ipv4(data)
    if ip is None:
        return None
    src, dst, proto, ihl, end, offset = ip
    names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    name = names.get(proto, 'OTHER')
    info = f'{src} -> {dst} | {name} | bytes={end}'
    payload = data[ihl:end]
    if offset:
        return name, info + f' | fragment_offset={offset} | data={payload[:16].hex()}'
    if proto == 6 and len(payload) >= 20:
        src_port, dst_port = struct.unpack('!HH', payload[:4])
        header_len = (payload[12] >> 4) * 4
        if header_len >= 20 and len(payload) >= header_len:
            info += f' | ports={src_port}->{dst_port}'
            payload = payload[header_len:]
    elif proto == 17 and len(payload) >= 8:
        src_port, dst_port, udp_len = struct.unpack('!HHH', payload[:6])
        info += f' | ports={src_port}->{dst_port}'
        payload = payload[8:min(len(payload), udp_len)] if udp_len >= 8 else b''
    info += f' | payload_preview_hex={payload[:16].hex() or "(empty)"}'
    return name, info


def main():
    parser = argparse.ArgumentParser(description='Authorized IPv4 traffic monitor')
    parser.add_argument('--host', default='0.0.0.0', help='Local IPv4 address to bind')
    parser.add_argument('--count', type=int, default=20, help='Maximum packets to capture')
    parser.add_argument('--log', default='network_log.txt', help='Output log filename')
    args = parser.parse_args()
    if args.count < 1:
        parser.error('--count must be at least 1')

    stats = Counter()
    captured = 0
    sock = None
    sniffing_enabled = False
    try:
        if socket.gethostname() and hasattr(socket, 'SIO_RCVALL'):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((args.host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            sniffing_enabled = True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.bind((args.host, 0))
        with open(args.log, 'w', encoding='utf-8') as log:
            header = f'Packet capture started: {datetime.now().isoformat(timespec="seconds")}\n'
            log.write(header)
            print(header.strip())
            while captured < args.count:
                data, _ = sock.recvfrom(65535)
                decoded = decode_packet(data)
                if decoded is None:
                    continue
                protocol, details = decoded
                stats[protocol] += 1
                captured += 1
                line = f'{datetime.now().isoformat(timespec="seconds")} | {details}'
                print(line)
                log.write(line + '\n')
            summary = '\nProtocol statistics:\n' + ''.join(
                f'{name}: {stats[name]}\n' for name in ('TCP', 'UDP', 'ICMP', 'OTHER')
            ) + f'TOTAL: {captured}\n'
            print(summary)
            log.write(summary)
    except PermissionError:
        print('Permission denied: run as Administrator (Windows) or root (Linux).')
    except OSError as error:
        print(f'Socket error: {error}. Try binding to your actual local IPv4 address.')
    except KeyboardInterrupt:
        print('\nCapture stopped by user.')
    finally:
        if sock is not None:
            if sniffing_enabled:
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            sock.close()


if __name__ == '__main__':
    main()
