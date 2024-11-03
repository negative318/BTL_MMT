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
import random as rd
import urllib.parse
class peer:
    def __init__(self, ip, port, tracker_url):
    
        self.max_piece_per_file = 4
        self.max_worker = 10
        self.ip = ip
        self.port = port
        self.tracker_url = tracker_url
        self.file_info_list = {}
        self.file_name = ""
        self.size = 0
        self.status = 0
        self.peer_id = ('-PC0001-' + ''.join([str(rd.randint(0, 9)) for i in range(12)])).encode()
        threading.Thread(target=self.start_upload_listener, daemon=True).start()

    def get_seeding(self):
        seeding_files = []
        for info_hash, info in self.file_info_list.items():
            seeding_files.append(info["file_path"])
        return seeding_files
    
    def get_status(self):
        status = f"ip: {self.ip}, port: {self.port}, file_name: {self.file_name}, size: {self.size}, status: {self.status: .2f}%"
        return status
        # return self.ip, self.port, self.file_name, self.size, self.status

    def start_upload_listener(self):
        try:
            self.upload_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.upload_socket.bind(("0.0.0.0", self.port))
            self.upload_socket.listen(5)
            print(f"Listening for upload connections on ip {self.ip} port {self.port}...")
        except Exception as e:
            print(f"Error in setting up listener: {e}")
            return

        while True:
            try:
                client_socket, address = self.upload_socket.accept()
                print(f"Connection received from {address}")

                threading.Thread(target=self.upload_piece_by_piece, args=(client_socket, address), daemon=True).start()

            except Exception as e:
                print(f"Error in handling connection: {e}")

    def is_download_complete(self, info_hash):

        file_info = self.file_info_list.get(info_hash)
        if not file_info:
            print("File info not found.")
            return False
        
        return all(file_info["pieces"])

    def register_files_with_tracker(self, file_path, status_file = "full"):

        torrent_file_path = self.create_torrent(file_path, self.tracker_url, "torrent")
        _, _, length, info_hash, _, piece_length = self.get_info(torrent_file_path)

        info_hash_bytes = urllib.parse.unquote_to_bytes(info_hash)
        info_hash_hex = info_hash_bytes.hex()
        num_pieces = math.ceil(length / piece_length)
        if status_file == "full":
            self.file_info_list[info_hash_hex] = {
                "file_path": file_path,
                "pieces": [True] * num_pieces
            }
        elif status_file == "empty":
            self.file_info_list[info_hash_hex] = {
                "file_path": file_path,
                "pieces": [False] * num_pieces
            }

        params = {
                "ip": self.ip,
                "port": self.port,
                "info_hash": info_hash,
                "peer_id": self.peer_id,
                "event": "started"
            }
        try:
            response = requests.get(self.tracker_url, params=params)
            if response.status_code == 200:
                print(f"Successfully sent info for file: {file_path}")
            else:
                print(f"Failed to send info for file: {file_path}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error connecting to tracker for file {file_path}: {e}")
        self.print_file_info_table()

    def disconnect_from_tracker(self):
        for info_hash in self.file_info_list.keys():
            params = {
                "ip": self.ip,
                "port": self.port,
                "info_hash": bytes.fromhex(info_hash),
                "peer_id": self.peer_id,
                "event": "end"
            }
            try:
                response = requests.get(self.tracker_url, params=params)
                if response.status_code == 200:
                    print("Successfully notified tracker of disconnection.")
                else:
                    print(f"Failed to notify tracker of disconnection. Status code: {response.status_code}")
            except Exception as e:
                print(f"Error connecting to tracker for disconnection: {e}")

    def print_file_info_table(self):
        headers = ["Info Hash", "File Path", "Pieces Count"]
        data = [
            [
                info_hash,
                file_info["file_path"],
                sum(file_info["pieces"])
            ]
            for info_hash, file_info in self.file_info_list.items()
        ]
        
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
        name = torrent_data["info"]["name"]
        tracker_url = torrent_data["announce"]
        length = torrent_data["info"]["length"]
        info_hash = hashlib.sha1(bencode.bencode(torrent_data['info'])).digest()
        piece_length = torrent_data['info']["piece length"]
        pieces = torrent_data["info"]["pieces"]
        return name, tracker_url, length, info_hash, pieces, piece_length

    def decode_bencode(self, bencoded_value):

        return bencode.decode(bencoded_value)

    def get_list_piece_hashs(self, pieces):
        list_pieces = []
        for i in range(0, len(pieces), 20):
            list_pieces.append(pieces[i:i+20].hex())
        return list_pieces

    def get_list_peers(self, tracker_url, info_hash, peer_id, uploaded, downloaded, left, compact):

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


    def add_to_seeding(self, file_path, info_hash, piece_length= 512*1024):

        length = os.path.getsize(file_path)
        info_hash_bytes = urllib.parse.unquote_to_bytes(info_hash)
        info_hash_hex = info_hash_bytes.hex()
        num_pieces = math.ceil(length / piece_length)
        self.file_info_list[info_hash_hex] = {
            "file_path": file_path,
            "pieces": [False] * num_pieces
        }

        params = {
                "ip": self.ip,
                "port": self.port,
                "info_hash": info_hash,
                "peer_id": self.peer_id,
                "event": "started"
            }
        try:
            response = requests.get(self.tracker_url, params=params)
            if response.status_code == 200:
                print(f"Successfully sent info for file: {file_path}")
            else:
                print(f"Failed to send info for file: {file_path}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error connecting to tracker for file {file_path}: {e}")
        # self.print_file_info_table()

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

    def download_piece(self, ip, port, length, info_hash, pieces, piece_length, peer_id):
        
        print(f"Attempting to connect to peer {ip}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        payload = (
            b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
            + info_hash
            + peer_id
        )

        try:
            sock.connect((ip, port))
            sock.sendall(payload)
            response = sock.recv(68)
            
            if response[28:48] != info_hash:
                raise Exception("Info hash does not match; invalid response from peer.")

            message = self.receive_message(sock)
            while int(message[4]) != 5:
                message = self.receive_message(sock)


            bitfield = message[5:]
            num_pieces = len(self.get_list_piece_hashs(pieces))
            peer_index = None

            info_hash_hex = info_hash.hex()
            



            for i in range(num_pieces):
                if info_hash_hex in self.file_info_list:
                    if self.file_info_list[info_hash_hex]["pieces"][i] == True:
                        continue
                    self.file_info_list[info_hash_hex]["pieces"][i] = True
                byte_index = i // 8
                bit_index = 7 - (i % 8)
                if bitfield[byte_index] & (1 << bit_index):
                    peer_index = i
                    break

            if peer_index is None:
                raise Exception("No available piece index found in bitfield.")

            interested_payload = struct.pack(">IB", 1, 2)
            sock.sendall(interested_payload)
            
            sock.settimeout(5)
            
            message = self.receive_message(sock)
            while int(message[4]) != 1:
                message = self.receive_message(sock)

            list_piece_hashes = self.get_list_piece_hashs(pieces)
            num_pieces = len(list_piece_hashes)

            if peer_index == num_pieces - 1:
                piece_length = length - piece_length * peer_index

            num_blocks = math.ceil(piece_length / (16 * 1024))
            data = bytearray()

            total_downloaded = 0
            for i in range(num_blocks):
                block_start = 16 * 1024 * i
                block_length = min(piece_length - block_start, 16 * 1024)
                request_payload = struct.pack(">IBIII", 13, 6, peer_index, block_start, block_length)
                sock.sendall(request_payload)
                message = self.receive_message(sock)
                data.extend(message[13:])
                total_downloaded += len(message[13:])

            

            return data, peer_index, total_downloaded

        except Exception as e:
            print(f"Error downloading piece from {ip}:{port} - {e}")
            if peer_index is not None and info_hash_hex in self.file_info_list:
                self.file_info_list[info_hash_hex]["pieces"][peer_index] = False
            return None, None, 0

        finally:
            sock.close()



    def download(self, torrent_file, output):
        name, tracker_url, length, info_hash, pieces, piece_length = self.get_info(torrent_file)
        
        self.file_name = name
        self.size = length
        piece_hashes = self.get_list_piece_hashs(pieces)
        num_pieces = len(piece_hashes)
        downloaded = 0

        with open(output, "wb") as f:
            f.truncate(length)

        self.add_to_seeding(output, info_hash)

        def write_piece_to_disk(data, piece_index):
                offset = piece_index * piece_length
                with open(output, "r+b") as f:
                    with mmap.mmap(f.fileno(), 0) as mm:
                        mm[offset:offset+len(data)] = data



        is_complete = self.is_download_complete(info_hash.hex())
        while(is_complete == False):

            list_peers = self.get_list_peers(tracker_url, info_hash, self.peer_id, 0, 0, length, 1)
            num_workers = min(self.max_worker, len(list_peers))
            with concurrent.futures.ThreadPoolExecutor(num_workers) as executor:
                
                futures = {
                    executor.submit(
                        self.download_piece, ip, port, length, info_hash, pieces, piece_length, self.peer_id
                    ): (ip, port)
                    for ip, port in list_peers
                }

                for future in concurrent.futures.as_completed(futures):
                    ip, port = futures[future]
                    try:
                        data, piece_index, piece_size = future.result()
                        if data is not None:
                            downloaded += piece_size
                            self.status = (downloaded / length) * 100
                            status = self.get_status()
                            print(status)
                            write_piece_to_disk(data, piece_index)
                        else:
                            print(f"Piece {piece_index} download failed.")
                    except Exception as e:
                        print(f"Error writing piece {piece_index}: {e}")
            is_complete = self.is_download_complete(info_hash.hex())
        print("Download complete.")
        return True



    def upload_piece_by_piece(self, client_socket, address, piece_length = 512 * 1024):


        
        def handle_peer_connection(client_socket, address):
            try:

                peer_handshake = client_socket.recv(68)
                incoming_info_hash = peer_handshake[28:48]
                peer_id = peer_handshake[48:]

                print(f"Connected with peer: {peer_id} in {address}")


                file_info = self.file_info_list.get(incoming_info_hash.hex())
                if file_info is None:
                    print("Requested file not found; closing connection.")
                    client_socket.close()
                    return

                file_path = file_info["file_path"]
                pieces = file_info["pieces"]

                handshake_response = (
                    b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00" +
                    incoming_info_hash +
                    self.peer_id
                )
                client_socket.sendall(handshake_response)


                num_pieces = len(pieces)
                bitfield = bytearray(math.ceil(num_pieces / 8))
                for i, piece_status in enumerate(pieces):
                    if piece_status:
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




if __name__ == "__main__":

    try:
        ip = "192.168.1.10"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        port = int(sys.argv[1])
        tracker_url = sys.argv[2]
        client = peer(ip, port, tracker_url)

        while True:

            user_input = input("input: ")
            if user_input == "exit":
                break
            elif "create_torrent" in user_input:
                parts = user_input.split(" ")
                num_file = len(parts)
                for i in range(1, num_file):
                    print(parts[i])
                    client.register_files_with_tracker(parts[i])
                print(client.get_seeding())
            elif "download" in user_input:
                parts = user_input.split(maxsplit=2)

                if len(parts) != 3:
                    print("Error: Please enter exactly three values: command, torrent_file, and output.")
                else:
                    command, torrent_file, output = parts

                    print(f"Command: {command}, Torrent file: {torrent_file}, Output: {output}")
                    client.download(torrent_file, output)
    finally:
        client.disconnect_from_tracker()

