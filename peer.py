#peer.py
import json
import sys
import hashlib
import bencode
import requests
import struct
import socket
import bencodepy
import math
import os
from urllib.parse import unquote
import threading
import concurrent.futures



def decode_bencode(bencoded_value):
    return bencode.decode(bencoded_value)


def get_info(torrent_file):
    with open(torrent_file, "rb") as f:
        torrent_data = bencode.decode(f.read())
    
    tracker_url = torrent_data["announce"]
    length = torrent_data["info"]["length"]
    info_hash = hashlib.sha1(bencode.bencode(torrent_data['info'])).digest()
    piece_length = torrent_data['info']["piece length"]
    pieces = torrent_data["info"]["pieces"]
    return tracker_url, length, info_hash, pieces, piece_length

def get_list_piece_hashs(pieces):
    list_pieces = []
    for i in range(0, len(pieces), 20):
        list_pieces.append(pieces[i:i+20].hex())
    return list_pieces

def get_list_peers(tracker_url, info_hash, peer_id, port, uploaded, downloaded, left, compact):

    list_peers = []

    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": uploaded,
        "downloaded": downloaded,
        "left": left,
        "compact": compact
    }

    response = requests.get(tracker_url, params = params)
    response_decode = decode_bencode(response.content)
    peers = response_decode["peers"]
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i: i+ 4])
        port = struct.unpack("!H", peers[i+4: i+6])[0]
        list_peers.append((ip, port))
    return list_peers

def handshake(info_hash, Ssocket, peer_id, ip, port):
    payload = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + peer_id.encode()
    )
    Ssocket.connect((ip, int(port)))
    Ssocket.send(payload)
    respon = Ssocket.recv(68)
    return respon

def receive_message(s):

    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message

def download_piece(tracker_url, length, info_hash, pieces, piece_length, peer_id, peer_index, output):
    # print("aaaaaaaaaaaaaaaaaaaa", tracker_url, info_hash.hex(), peer_id, 6881, 0, 0, length, 1)
    list_peers = get_list_peers(tracker_url, info_hash, peer_id, 6881, 0, 0, length, 1)
    ip, port = list_peers[0]
    # ip = '192.168.1.10'
    # port = 2000
    print(ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    payload = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + peer_id.encode()
    )


    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        response = sock.recv(68)
        
        message = receive_message(sock)
        print(message)
        while int(message[4]) != 5:
            message = receive_message(sock)
        

        interested_payload = struct.pack(">IB", 1, 2)
        print(interested_payload)
        sock.sendall(interested_payload)
        
        sock.settimeout(3)
        
        message = receive_message(sock)

        while int(message[4]) != 1:
            message =receive_message(sock)

        list_piece_hashs = get_list_piece_hashs(pieces)
        num_peers = len(list_piece_hashs)

        if peer_index == num_peers - 1:
            piece_length = length - piece_length * peer_index
        
        num_blocks = math.ceil(piece_length / (16*1024))

        data = bytearray()

        for i in range(num_blocks):
            block_start = 16 * 1024 * i
            block_length = min(piece_length - block_start, 16*1024)
            print(f"request block {i+1} of {num_blocks} with len {block_length}")

            request_payload = struct.pack(">IBIII", 13, 6, peer_index, block_start, block_length)

            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        
        with open(output, "ab") as f:
            f.write(data)
        print("end file")
        data.clear()

    finally:
        print("close socket")
        sock.close()

    return True

def download(torrent_file, output):

    tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
    num_piece = len(get_list_piece_hashs(pieces))
    for i in range(num_piece):
        download_piece(tracker_url, length, info_hash, pieces, piece_length, "01234567899876543210", i, output)
    return True





# def download_piece(tracker_url, length, info_hash, pieces, piece_length, peer_id, peer_index):

#     # print("aaaaaaaaaaaaaaaaaaaa", tracker_url, info_hash.hex(), peer_id, 6881, 0, 0, length, 1)
#     list_peers = get_list_peers(tracker_url, info_hash, peer_id, 6881, 0, 0, length, 1)
#     ip, port = list_peers[0]
#     # ip = '192.168.0.191'
#     # port = 6881
#     print(ip, port)
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     payload = (
#         b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
#         + info_hash
#         + peer_id.encode()
#     )

#     try:
#         sock.connect((ip, port))
#         sock.sendall(payload)
#         response = sock.recv(68)
        
#         message = receive_message(sock)
#         while int(message[4]) != 5:
#             message = receive_message(sock)

#         interested_payload = struct.pack(">IB", 1, 2)
#         sock.sendall(interested_payload)
        
#         sock.settimeout(3)
        
#         message = receive_message(sock)
#         while int(message[4]) != 1:
#             message = receive_message(sock)

#         list_piece_hashes = get_list_piece_hashs(pieces)
#         num_pieces = len(list_piece_hashes)

#         if peer_index == num_pieces - 1:
#             piece_length = length - piece_length * peer_index

#         num_blocks = math.ceil(piece_length / (16 * 1024))
#         data = bytearray()

#         for i in range(num_blocks):
#             block_start = 16 * 1024 * i
#             block_length = min(piece_length - block_start, 16 * 1024)
#             print(f"Requesting block {i+1} of {num_blocks} for piece {peer_index} with length {block_length}")

#             request_payload = struct.pack(">IBIII", 13, 6, peer_index, block_start, block_length)
#             sock.sendall(request_payload)
#             message = receive_message(sock)
#             data.extend(message[13:])
        
#         print(f"Piece {peer_index} downloaded successfully.")
#         return data

#     finally:
#         print(f"Closing connection to peer for piece {peer_index}")
#         sock.close()


# def download(torrent_file, output):
#     tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
#     piece_hashes = get_list_piece_hashs(pieces)
#     num_pieces = len(piece_hashes)

#     downloaded_pieces = [None] * num_pieces
    
#     with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
#         futures = {
#             executor.submit(download_piece, tracker_url, length, info_hash, pieces, piece_length, "01234567899876543210", i): i
#             for i in range(num_pieces)
#         }
        
#         for future in concurrent.futures.as_completed(futures):
#             piece_index = futures[future]
#             try:
#                 data = future.result()
#                 downloaded_pieces[piece_index] = data
#                 print(f"Piece {piece_index} stored successfully.")
#             except Exception as e:
#                 print(f"Piece {piece_index} download failed: {e}")


#     with open(output, "wb") as f:
#         for i, piece in enumerate(downloaded_pieces):
#             if piece is not None:
#                 f.write(piece)
#             else:
#                 print(f"Warning: Piece {i} is missing and was not downloaded.")


def upload_piece_by_piece(torrent_file, file_path, peer_id="01234567899876543211", port=6881):

    tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", port))
    server_socket.listen(5)
    print(f"Đang lắng nghe kết nối trên cổng {port}...")

    def handle_peer_connection(client_socket, address):
        try:
            print(f"Kết nối với peer: {address}")

            peer_handshake = client_socket.recv(68)
            if peer_handshake[28:48] != info_hash:
                print("Info hash không khớp; đóng kết nối")
                client_socket.close()
                return


            handshake_response = (
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00" +
                info_hash +
                peer_id.encode()
            )
            client_socket.sendall(handshake_response)


            num_pieces = len(get_list_piece_hashs(pieces))
            bitfield = bytearray(math.ceil(num_pieces / 8))
            for i in range(num_pieces):
                byte_index = i // 8
                bit_index = 7 - (i % 8)
                bitfield[byte_index] |= (1 << bit_index)


            bitfield_msg = struct.pack(">IB", len(bitfield) + 1, 5) + bitfield
            client_socket.sendall(bitfield_msg)
            
            while True:
                message = receive_message(client_socket)
                if message is None:
                    break

                message_id = message[4]
                if message_id == 2:
                    print("Nhận được thông điệp 'interested' từ peer")
                    unchoke_msg = struct.pack(">IB", 1, 1)
                    client_socket.sendall(unchoke_msg)
                elif message_id == 6:
                    index, offset, length = struct.unpack(">III", message[5:17])
                    piece_start = index * piece_length + offset
                    with open(file_path, "rb") as f:
                        f.seek(piece_start)
                        data_to_send = f.read(length)
                    piece_msg = struct.pack(">IBII", 9 + len(data_to_send), 7, index, offset) + data_to_send
                    client_socket.sendall(piece_msg)
                    print(f"send {index} offset {offset} length {length} to peer {address}")
                else:
                    print(f"Nhận được thông điệp không xác định với ID: {message_id}")

        except Exception as e:
            print(f"Lỗi với peer {address}: {e}")
        finally:
            client_socket.close()
            print(f"Kết nối với peer {address} đã đóng")


    try:
        while True:
            client_socket, address = server_socket.accept()
            peer_thread = threading.Thread(target=handle_peer_connection, args=(client_socket, address))
            peer_thread.start()
    except KeyboardInterrupt:
        print("Dừng server upload.")
    finally:
        server_socket.close()




def get_piece_hashes(file_path, piece_length):

    piece_hashes = b""
    with open(file_path, "rb") as f:
        while True:
            piece = f.read(piece_length)
            if not piece:
                break
            piece_hash = hashlib.sha1(piece).digest()
            piece_hashes += piece_hash
    return piece_hashes

def create_torrent(file_path, tracker_url, piece_length=512*1024):
 
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    piece_hashes = get_piece_hashes(file_path, piece_length)
    print(tracker_url, file_name, file_size, piece_length, piece_hashes)
    torrent_info = {
        "announce": tracker_url,
        "info": {
            "name": file_name,
            "length": file_size,
            "piece length": piece_length,
            "pieces": piece_hashes,
        }
    }

    torrent_file_path = f"{file_name}.torrent"
    with open(torrent_file_path, "wb") as torrent_file:
        torrent_file.write(bencodepy.encode(torrent_info))


    print(f"Torrent file created: {torrent_file_path}")
    return torrent_file_path


def main():
    command = sys.argv[1]
    port = 55768


    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        torrent_file = sys.argv[2]
        
        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
        piece_hashs = get_list_piece_hashs(pieces)
        print("Tracker URL:", tracker_url)
        print("Length:", length)
        print("Info Hash:", info_hash.hex())
        print("Piece Length:", piece_length)
        print("Piece Hashes:")
        for i in range(len(piece_hashs)):
            print(piece_hashs[i])

    elif command == "peers":
        torrent_file = sys.argv[2]
        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
        list_peers = get_list_peers(tracker_url, info_hash, "01234567899876543210", 6881, 0, 0, length, 1)


        for i in range(0, len(list_peers)):
            print(f"Peers: {list_peers[i][0]}:{list_peers[i][1]}")



    elif command == "handshake":
        torrent_file = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")

        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)

        Ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        respon = handshake(info_hash, Ssocket, "01234567899876543210", ip, port)
        print(f"Peer ID: {respon[48:].hex()}")


    elif command == "download_piece":
        output = sys.argv[3]
        torrent_file = sys.argv[4]
        peer_index = int(sys.argv[5])
        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)

        if download_piece(tracker_url, length, info_hash, pieces, piece_length, "01234567899876543210", peer_index, output):
            print(f"Piece {peer_index} downloaded to {output}")
        
        else:
            raise RuntimeError("Failed to download piece")


    elif command == "download":
        output = sys.argv[3]
        torrent_file = sys.argv[4]

        if download(torrent_file, output):
            print(f"download {torrent_file} to {output}")


    elif command == "upload":
        torrent_file = sys.argv[2]
        file_path = sys.argv[3]
        upload_piece_by_piece(torrent_file, file_path, peer_id="01234567899876543210", port=2000)

    elif command == "create_torrent":
        # http://192.168.150.190:6881/announce
        file_path = sys.argv[2]
        tracker_url = sys.argv[3]
        create_torrent(file_path, tracker_url)



    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
