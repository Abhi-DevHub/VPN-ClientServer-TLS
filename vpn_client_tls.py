import socket
import ssl
import threading
import os

SERVER_IP = '127.0.0.1'  # Change to your server's IP
SERVER_PORT = 8443
NICKNAME = input("Enter your nickname: ")

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # In production, use cert verification

def recvall(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Disconnected")
        data += chunk
    return data

def handle_receive(conn):
    try:
        while True:
            header = conn.recv(1)
            if not header:
                break
            msg_type = header.decode()

            if msg_type == 'M':  # Message
                msg_len = int.from_bytes(conn.recv(2), 'big')
                msg = recvall(conn, msg_len).decode()
                print(f"\n[Message] {msg}")

            elif msg_type == 'F':  # File incoming
                sender_len = int.from_bytes(conn.recv(1), 'big')
                sender = recvall(conn, sender_len).decode()

                filename_len = int.from_bytes(conn.recv(1), 'big')
                filename = recvall(conn, filename_len).decode()

                filesize = int.from_bytes(conn.recv(4), 'big')
                filedata = recvall(conn, filesize)

                save_path = f"received_from_{sender}_{filename}"
                with open(save_path, "wb") as f:
                    f.write(filedata)
                print(f"\n[File] Received '{filename}' ({filesize} bytes) from {sender}. Saved as: {save_path}")
    except Exception as e:
        print(f"[-] Connection error: {e}")
    finally:
        conn.close()

def main():
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(raw_sock, server_hostname=SERVER_IP)
    conn.connect((SERVER_IP, SERVER_PORT))

    # Send nickname
    conn.send(len(NICKNAME.encode()).to_bytes(1, 'big') + NICKNAME.encode())
    print(f"[+] Connected to server as {NICKNAME}")

    # Start receiver thread
    threading.Thread(target=handle_receive, args=(conn,), daemon=True).start()

    while True:
        try:
            cmd = input("\nEnter command [msg | file | exit]: ").strip().lower()
            if cmd == "msg":
                recipient = input("To: ").strip()
                message = input("Message: ").strip()
                full_msg = f"{recipient}:{message}".encode()
                conn.send(b'M' + len(full_msg).to_bytes(2, 'big') + full_msg)

            elif cmd == "file":
                recipient = input("Send file to: ").strip()
                filepath = input("Path to file: ").strip()

                if not os.path.exists(filepath):
                    print("[-] File not found.")
                    continue

                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)
                with open(filepath, "rb") as f:
                    filedata = f.read()

                conn.send(b'F')
                conn.send(len(recipient.encode()).to_bytes(1, 'big') + recipient.encode())
                conn.send(len(filename.encode()).to_bytes(1, 'big') + filename.encode())
                conn.send(len(filedata).to_bytes(4, 'big') + filedata)
                print(f"[+] Sent '{filename}' ({filesize} bytes) to {recipient}")

            elif cmd == "exit":
                print("[*] Disconnecting...")
                conn.close()
                break

            else:
                print("Unknown command. Use: msg | file | exit")
        except Exception as e:
            print(f"[!] Error: {e}")
            break

if __name__ == "__main__":
    main()
