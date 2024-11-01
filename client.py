#client.py
import sys
import hashlib
import bencode
import requests
import struct
import socket
import bencodepy
import math
import os
import threading
import concurrent.futures
from tabulate import tabulate
import mmap
import requests

class peer:
    def __init__(self, ip, port, tracker_ip, tracker_port):
        
        
        self.ip = ip
        self.port = port
        self.tracker_ip = tracker_ip
        self.tracker_port = tracker_port
        self.tracker_url = f"http://{tracker_ip}:{tracker_port}/announce"

        self.file_info_list = {}
        self.register_files_with_tracker()

        threading.Thread(target=self.start_upload_listener, daemon=True).start()


    def start_upload_listener(self, torrent_file= "torrent/ML.docx.torrent", file_path = "file/ML.docx"):
        try:
            self.upload_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.upload_socket.bind((self.ip, self.port))
            self.upload_socket.listen(5)
            print(f"Listening for upload connections on ip {self.ip} port {self.port}...")
        except Exception as e:
            print(f"Error in setting up listener: {e}")
            return

        while True:
            try:
                client_socket, address = self.upload_socket.accept()
                print(f"Connection received from {address}")

                threading.Thread(target=self.upload_piece_by_piece, args=(client_socket, address, torrent_file, file_path), daemon=True).start()

            except Exception as e:
                print(f"Error in handling connection: {e}")


    def register_files_with_tracker(self):
        files = os.listdir("file")
        for file in files:
            file_path = os.path.join("file", file)
            torrent_file_path = self.create_torrent(file_path, self.tracker_url, "torrent")
            _, _, info_hash, _, _ = self.get_info(torrent_file_path)
            info_hash_hex = info_hash.hex()
            self.file_info_list[info_hash_hex] = file_path

            params = {
                "ip": self.ip,
                "port": self.port,
                "info_hash": info_hash,
                "event": "started"
            }
            try:
                response = requests.get(self.tracker_url, params=params)
                if response.status_code == 200:
                    print(f"Successfully sent info for file: {file}")
                else:
                    print(f"Failed to send info for file: {file}. Status code: {response.status_code}")
            except Exception as e:
                print(f"Error connecting to tracker for file {file}: {e}")
        self.print_file_info_table()

    def print_file_info_table(self):
        # Tạo bảng từ dictionary
        headers = ["Info Hash", "File Path"]
        data = [[info_hash, file_path] for info_hash, file_path in self.file_info_list.items()]
        
        # In bảng sử dụng tabulate
        print(tabulate(data, headers=headers, tablefmt="grid"))







    def create_torrent(self, file_path, tracker_url, folder_out = "torrent", piece_length=512*1024):
    
        os.makedirs(folder_out, exist_ok=True)

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        piece_hashes = self.get_piece_hashes(file_path, piece_length)
        torrent_info = {
            "announce": tracker_url,
            "info": {
                "name": file_name,
                "length": file_size,
                "piece length": piece_length,
                "pieces": piece_hashes,
            }
        }

        torrent_file_path = os.path.join(folder_out, f"{file_name}.torrent")
        with open(torrent_file_path, "wb") as torrent_file:
            torrent_file.write(bencodepy.encode(torrent_info))


        print(f"Torrent file created: {torrent_file_path}")
        return torrent_file_path

    def get_info(self, torrent_file):
        with open(torrent_file, "rb") as f:
            torrent_data = bencode.decode(f.read())
        
        tracker_url = torrent_data["announce"]
        length = torrent_data["info"]["length"]
        info_hash = hashlib.sha1(bencode.bencode(torrent_data['info'])).digest()
        piece_length = torrent_data['info']["piece length"]
        pieces = torrent_data["info"]["pieces"]
        return tracker_url, length, info_hash, pieces, piece_length

    def decode_bencode(self, bencoded_value):

        return bencode.decode(bencoded_value)

        with open(torrent_file, "rb") as f:
            torrent_data = bencode.decode(f.read())
        
        tracker_url = torrent_data["announce"]
        length = torrent_data["info"]["length"]
        info_hash = hashlib.sha1(bencode.bencode(torrent_data['info'])).digest()
        piece_length = torrent_data['info']["piece length"]
        pieces = torrent_data["info"]["pieces"]
        return tracker_url, length, info_hash, pieces, piece_length
    
    def get_list_piece_hashs(self, pieces):
        list_pieces = []
        for i in range(0, len(pieces), 20):
            list_pieces.append(pieces[i:i+20].hex())
        return list_pieces

    def get_list_peers(self, tracker_url, info_hash, peer_id, port, uploaded, downloaded, left, compact):

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
        response_decode = self.decode_bencode(response.content)
        peers = response_decode["peers"]
        for i in range(0, len(peers), 6):
            ip = ".".join(str(b) for b in peers[i: i+ 4])
            port = struct.unpack("!H", peers[i+4: i+6])[0]
            list_peers.append((ip, port))
        return list_peers

    def handshake(self, info_hash, Ssocket, peer_id, ip, port):
        payload = (
            b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
            + info_hash
            + peer_id.encode()
        )
        Ssocket.connect((ip, int(port)))
        Ssocket.send(payload)
        respon = Ssocket.recv(68)
        return respon

    def get_piece_hashes(self, file_path, piece_length):

        piece_hashes = b""
        with open(file_path, "rb") as f:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                piece_hash = hashlib.sha1(piece).digest()
                piece_hashes += piece_hash
        return piece_hashes

    def receive_message(self, s):

        length = s.recv(4)
        while not length or not int.from_bytes(length):
            length = s.recv(4)
        message = s.recv(int.from_bytes(length))
        while len(message) < int.from_bytes(length):
            message += s.recv(int.from_bytes(length) - len(message))
        return length + message

    def download_piece(self, tracker_url, length, info_hash, pieces, piece_length, peer_id, peer_index):


        list_peers = self.get_list_peers(tracker_url, info_hash, peer_id, 6881, 0, 0, length, 1)
        ip, port = list_peers[0]
        # ip = '192.168.0.191'
        # port = 6881
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
            
            message = self.receive_message(sock)
            while int(message[4]) != 5:
                message = self.receive_message(sock)

            interested_payload = struct.pack(">IB", 1, 2)
            sock.sendall(interested_payload)
            
            sock.settimeout(10)
            
            message = self.receive_message(sock)
            while int(message[4]) != 1:
                message = self.receive_message(sock)

            list_piece_hashes = self.get_list_piece_hashs(pieces)
            num_pieces = len(list_piece_hashes)

            if peer_index == num_pieces - 1:
                piece_length = length - piece_length * peer_index

            num_blocks = math.ceil(piece_length / (16 * 1024))
            data = bytearray()

            for i in range(num_blocks):
                block_start = 16 * 1024 * i
                block_length = min(piece_length - block_start, 16 * 1024)
                print(f"Requesting block {i+1} of {num_blocks} for piece {peer_index} with length {block_length}")

                request_payload = struct.pack(">IBIII", 13, 6, peer_index, block_start, block_length)
                sock.sendall(request_payload)
                message = self.receive_message(sock)
                data.extend(message[13:])
            
            print(f"Piece {peer_index} downloaded successfully.")
            return data

        finally:
            print(f"Closing connection to peer for piece {peer_index}")
            sock.close()



    def download(self, torrent_file, output):
        tracker_url, length, info_hash, pieces, piece_length = self.get_info(torrent_file)
        piece_hashes = self.get_list_piece_hashs(pieces)
        num_pieces = len(piece_hashes)

        with open(output, "wb") as f:
            f.truncate(length)

        def write_piece_to_disk(data, piece_index):
            offset = piece_index * piece_length
            with open(output, "r+b") as f:
                with mmap.mmap(f.fileno(), 0) as mm:
                    mm[offset:offset+len(data)] = data

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(self.download_piece, tracker_url, length, info_hash, pieces, piece_length, "01234567899876543210", i): i
                for i in range(num_pieces)
            }

            for future in concurrent.futures.as_completed(futures):
                piece_index = futures[future]
                try:
                    data = future.result()
                    if data is not None:
                        write_piece_to_disk(data, piece_index)
                        print(f"Piece {piece_index} stored successfully on disk.")
                    else:
                        print(f"Piece {piece_index} download failed.")
                except Exception as e:
                    print(f"Error writing piece {piece_index}: {e}")

        print("Download complete.")
        return True



    def upload_piece_by_piece(self, client_socket, address, torrent_file, file_path, peer_id="01234567899876543211", port=6881):

        tracker_url, length, info_hash, pieces, piece_length = self.get_info(torrent_file)

        def handle_peer_connection(client_socket, address):
            try:
                print(f"Connected with peer: {address}")

                peer_handshake = client_socket.recv(68)
                if peer_handshake[28:48] != info_hash:
                    print("Info hash does not match; closing connection")
                    client_socket.close()
                    return

                handshake_response = (
                    b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00" +
                    info_hash +
                    peer_id.encode()
                )
                client_socket.sendall(handshake_response)

                num_pieces = len(self.get_list_piece_hashs(pieces))
                bitfield = bytearray(math.ceil(num_pieces / 8))
                for i in range(num_pieces):
                    byte_index = i // 8
                    bit_index = 7 - (i % 8)
                    bitfield[byte_index] |= (1 << bit_index)

                bitfield_msg = struct.pack(">IB", len(bitfield) + 1, 5) + bitfield
                client_socket.sendall(bitfield_msg)

                while True:
                    message = self.receive_message(client_socket)
                    if message is None:
                        break

                    message_id = message[4]
                    
                    if message_id == 2:
                        print("Received 'interested' message from peer")
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
                        print(f"Sent piece {index}, offset {offset}, length {length} to peer {address}")
                    else:
                        print(f"Received unknown message ID: {message_id} from peer")

            except Exception as e:
                print(f"Error with peer {address}: {e}")
            finally:
                client_socket.close()
                print(f"Connection with peer {address} closed")

        handle_peer_connection(client_socket, address)

    def get_piece_hashes(self, file_path, piece_length):

        piece_hashes = b""
        with open(file_path, "rb") as f:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                piece_hash = hashlib.sha1(piece).digest()
                piece_hashes += piece_hash
        return piece_hashes



if __name__ == "__main__":


    ip = "192.168.1.9"
    port = int(sys.argv[1])
    tracker = sys.argv[2].split(":")
    tracker_ip = tracker[0]
    tracker_port = int(tracker[1])
    print(tracker, tracker_ip, tracker_port)
    client = peer(ip, port, tracker_ip, tracker_port)

    while True:

        user_input = input("input: ")

        parts = user_input.split(maxsplit=2)

        if len(parts) != 3:
            print("Error: Please enter exactly three values: command, torrent_file, and output.")
        else:
            command, torrent_file, output = parts

            print(f"Command: {command}, Torrent file: {torrent_file}, Output: {output}")
            if command == "download":
                client.download(torrent_file, output)

