import socket
import sys
import time
from struct import *
import argparse

# Constants
HEADER_FORMAT = '!IHH'
HEADER_SIZE = calcsize(HEADER_FORMAT)  # 4 + 2 + 2 = 8 bytes
MAX_PAYLOAD = 1464  # 1472 - 8
TIMEOUT = 1

# Flag values
FLAG_SYN = 0b1000
FLAG_ACK = 0b0100
FLAG_FIN = 0b0010

def create_packet(seq, flags, win, data):
    header = pack(HEADER_FORMAT, seq, flags, win)
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

    # Handshake
    seq = 0
    sock.sendto(create_packet(seq, FLAG_SYN, 0, b''), addr)
    try:
        resp, _ = sock.recvfrom(1472)
        r_seq, flags, _ = parse_header(resp[:HEADER_SIZE])
        if flags & FLAG_SYN and flags & FLAG_ACK:
            sock.sendto(create_packet(seq + 1, FLAG_ACK, 0, b''), addr)
        else:
            print("Handshake failed")
            return
    except socket.timeout:
        print("Timeout during handshake")
        return

    # File transfer
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
                pkt = create_packet(next_seq, 0, 0, data)
                sock.sendto(pkt, addr)
                window[next_seq] = (pkt, time.time())
                next_seq += 1

            try:
                resp, _ = sock.recvfrom(1472)
                ack_seq, flags, _ = parse_header(resp[:HEADER_SIZE])
                if flags & FLAG_ACK and ack_seq in window:
                    del window[ack_seq]
                    if ack_seq == base:
                        while base not in window and base < next_seq:
                            base += 1
            except socket.timeout:
                for seq_num, (pkt, sent_time) in list(window.items()):
                    if time.time() - sent_time > TIMEOUT:
                        sock.sendto(pkt, addr)
                        window[seq_num] = (pkt, time.time())

    # Teardown
    sock.sendto(create_packet(next_seq, FLAG_FIN, 0, b''), addr)
    try:
        data, _ = sock.recvfrom(1472)
        _, flags, _ = parse_header(data[:HEADER_SIZE])
        if flags & FLAG_ACK:
            print("Teardown complete")
    except socket.timeout:
        print("Timeout during teardown")

    sock.close()

def server_mode(outfile, listen_ip, listen_port, discard=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, listen_port))
    print(f"Server listening on {listen_ip}:{listen_port}")

    expected_seq = 0
    drop_once = discard

    with open(outfile, 'wb') as f:
        while True:
            data, addr = sock.recvfrom(1472)
            header = data[:HEADER_SIZE]
            payload = data[HEADER_SIZE:]
            seq, flags, win = parse_header(header)

            if flags & FLAG_SYN:
                response = create_packet(0, FLAG_SYN | FLAG_ACK, 0, b'')
                sock.sendto(response, addr)
            elif flags & FLAG_ACK:
                continue
            elif flags & FLAG_FIN:
                ack_pkt = create_packet(seq, FLAG_ACK, 0, b'')
                sock.sendto(ack_pkt, addr)
                break
            else:
                if discard and drop_once and seq == expected_seq:
                    print(f"Dropping packet seq={seq} for test")
                    drop_once = False
                    continue
                if seq == expected_seq:
                    f.write(payload)
                    ack_pkt = create_packet(seq, FLAG_ACK, 0, b'')
                    sock.sendto(ack_pkt, addr)
                    expected_seq += 1
                else:
                    ack_pkt = create_packet(expected_seq - 1, FLAG_ACK, 0, b'')
                    sock.sendto(ack_pkt, addr)

    sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['send', 'receive'])
    parser.add_argument('file')
    parser.add_argument('ip')
    parser.add_argument('port', type=int)
    parser.add_argument('--window', type=int, help='Sliding window size (client only)')
    parser.add_argument('-d', '--discard', action='store_true', help='Server drops one packet to test retransmission')
    args = parser.parse_args()

    if args.mode == 'send':
        if args.window is None:
            print("Client mode requires --window")
            sys.exit(1)
        client_mode(args.file, args.ip, args.port, args.window)
    else:
        server_mode(args.file, args.ip, args.port, discard=args.discard)
