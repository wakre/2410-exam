import socket
import sys
import threading
import time
from struct import *

# Constants
HEADER_FORMAT = '!IIHH'
HEADER_SIZE = calcsize(HEADER_FORMAT)
MAX_PAYLOAD = 1460
TIMEOUT = 1

# Flag values
FLAG_SYN = 0b1000
FLAG_ACK = 0b0100
FLAG_FIN = 0b0010


def create_packet(seq, ack, flags, win, data):
    header = pack(HEADER_FORMAT, seq, ack, flags, win)
    return header + data

def parse_header(header):
    return unpack(HEADER_FORMAT, header)

def parse_flags(flags):
    syn = (flags >> 3) & 1
    ack = (flags >> 2) & 1
    fin = (flags >> 1) & 1
    return syn, ack, fin


def client_mode(filename, server_ip, server_port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    addr = (server_ip, server_port)

    # 1. Handshake
    seq = 0
    syn_packet = create_packet(seq, 0, FLAG_SYN, 0, b'')
    sock.sendto(syn_packet, addr)

    try:
        data, _ = sock.recvfrom(1472)
        _, ack, flags, _ = parse_header(data[:HEADER_SIZE])
        if flags & FLAG_SYN and flags & FLAG_ACK:
            ack_packet = create_packet(seq + 1, ack + 1, FLAG_ACK, 0, b'')
            sock.sendto(ack_packet, addr)
        else:
            print("Handshake failed")
            return
    except socket.timeout:
        print("Timeout during handshake")
        return

    # 2. File transfer with sliding window
    with open(filename, 'rb') as f:
        base = 0
        next_seq = 0
        window = {}
        eof = False

        while not eof or window:
            while next_seq < base + window_size and not eof:
                data = f.read(MAX_PAYLOAD)
                if not data:
                    eof = True
                    break
                pkt = create_packet(next_seq, 0, 0, 0, data)
                sock.sendto(pkt, addr)
                window[next_seq] = (pkt, time.time())
                next_seq += 1

            try:
                resp, _ = sock.recvfrom(1472)
                _, ack_num, flags, _ = parse_header(resp[:HEADER_SIZE])
                if flags & FLAG_ACK and ack_num in window:
                    del window[ack_num]
                    if ack_num == base:
                        base += 1
            except socket.timeout:
                for k, (pkt, sent_time) in window.items():
                    if time.time() - sent_time > TIMEOUT:
                        sock.sendto(pkt, addr)
                        window[k] = (pkt, time.time())

    # 3. Connection teardown
    fin_packet = create_packet(next_seq, 0, FLAG_FIN, 0, b'')
    sock.sendto(fin_packet, addr)
    try:
        data, _ = sock.recvfrom(1472)
        _, _, flags, _ = parse_header(data[:HEADER_SIZE])
        if flags & FLAG_ACK:
            print("Teardown complete")
    except socket.timeout:
        print("Timeout during teardown")

    sock.close()


def server_mode(output_file, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"Server listening on {ip}:{port}")

    expected_seq = 0
    with open(output_file, 'wb') as f:
        while True:
            data, addr = sock.recvfrom(1472)
            header = data[:HEADER_SIZE]
            payload = data[HEADER_SIZE:]
            seq, ack, flags, win = parse_header(header)

            if flags & FLAG_SYN:
                synack = create_packet(0, seq, FLAG_SYN | FLAG_ACK, 0, b'')
                sock.sendto(synack, addr)
            elif flags & FLAG_ACK:
                continue  # part of handshake or teardown
            elif flags == 0:
                if seq == expected_seq:
                    f.write(payload)
                    ack_pkt = create_packet(0, seq, FLAG_ACK, 0, b'')
                    sock.sendto(ack_pkt, addr)
                    expected_seq += 1
                else:
                    # resend last ACK
                    ack_pkt = create_packet(0, expected_seq - 1, FLAG_ACK, 0, b'')
                    sock.sendto(ack_pkt, addr)
            elif flags & FLAG_FIN:
                ack_pkt = create_packet(0, seq, FLAG_ACK, 0, b'')
                sock.sendto(ack_pkt, addr)
                break

    sock.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python application.py send <file> <server_ip> <server_port> <window_size>")
        print("  python application.py receive <outfile> <listen_ip> <listen_port>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'send' and len(sys.argv) == 6:
        filename = sys.argv[2]
        server_ip = sys.argv[3]
        server_port = int(sys.argv[4])
        window_size = int(sys.argv[5])
        client_mode(filename, server_ip, server_port, window_size)
    elif mode == 'receive' and len(sys.argv) == 5:
        output_file = sys.argv[2]
        listen_ip = sys.argv[3]
        listen_port = int(sys.argv[4])
        server_mode(output_file, listen_ip, listen_port)
    else:
        print("Invalid arguments.")
