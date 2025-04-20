# vpn_server_tls.py
import socket
import ssl
import threading
import os
import logging
import time
from datetime import datetime

# Setup logging
logging.basicConfig(filename='vpn_server_tls.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

clients = {}  # nickname -> conn
client_addresses = {}  # nickname -> addr
clients_lock = threading.Lock()
last_activity = {}  # nickname -> timestamp (updated on any message or heartbeat response from client)

SERVER_CERT = 'server_cert.pem'
SERVER_KEY = 'server_key.pem'
BUFFER_SIZE = 4096
TIMEOUT = 60  # seconds (Reduced for quicker testing, increase as needed)
HEARTBEAT_INTERVAL = 20 # seconds (Server sends probes)
HEARTBEAT_TIMEOUT_FACTOR = 3 # Client must respond within N * HEARTBEAT_INTERVAL


def recvall(sock, size):
    """Receives exactly 'size' bytes from the socket."""
    data = b''
    while len(data) < size:
        try:
            chunk = sock.recv(min(BUFFER_SIZE, size - len(data)))
            if not chunk:
                # Connection closed gracefully or unexpectedly by the client
                logging.debug(f"Socket recv returned empty chunk for sock {sock.fileno()}. Expected {size-len(data)} more bytes.")
                raise ConnectionError("Client disconnected")
        except socket.timeout:
            logging.warning(f"Socket timeout while receiving data for sock {sock.fileno()}.")
            raise ConnectionError("Socket timeout during recvall")
        except ssl.SSLWantReadError:
            # Should not happen with blocking sockets, but handle defensively
            time.sleep(0.1)
            continue
        except OSError as e:
            logging.error(f"Socket error during recvall for sock {sock.fileno()}: {e}")
            raise ConnectionError(f"Socket error: {e}")
        data += chunk
    return data

def broadcast_user_list():
    """Send updated user list to all connected clients."""
    with clients_lock:
        if not clients:
            return

        user_list_str = ",".join(sorted(clients.keys()))
        user_list_data = user_list_str.encode('utf-8')
        payload = b'U' + len(user_list_data).to_bytes(2, 'big') + user_list_data
        logging.debug(f"Broadcasting user list: {user_list_str}")

        disconnected_on_broadcast = []
        for nickname, client_conn in clients.items():
            try:
                client_conn.sendall(payload)
            except Exception as e:
                logging.warning(f"Failed to send user list to {nickname}: {e}. Marking for removal.")
                disconnected_on_broadcast.append(nickname)

        # Handle clients that failed during broadcast (rare but possible)
        if disconnected_on_broadcast:
             # Need to release lock to call cleanup function which acquires it again
            needs_rebroadcast = bool(disconnected_on_broadcast) # Check if we actually removed someone
            logging.info(f"Removing clients disconnected during user list broadcast: {disconnected_on_broadcast}")
            # Don't call cleanup directly while holding the lock
            # The heartbeat monitor will eventually clean them up, or their handler thread will

    # No rebroadcast here to avoid potential loops. Heartbeat or next event will trigger it.


def cleanup_client(nickname):
    """Safely removes a client and notifies others."""
    disconnected = False
    with clients_lock:
        logging.debug(f"Attempting cleanup for nickname: {nickname}")
        conn = clients.pop(nickname, None)
        client_addresses.pop(nickname, None)
        last_activity.pop(nickname, None)

        if conn:
            disconnected = True
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            finally:
                 try:
                     conn.close()
                 except OSError:
                     pass # Ignore if already closed
            logging.info(f"Cleaned up client {nickname}")
        else:
            logging.debug(f"Client {nickname} already cleaned up or never fully added.")

    # Broadcast user list update *after* releasing the lock
    if disconnected:
        broadcast_user_list()


def heartbeat_monitor():
    """Thread that monitors client activity and sends heartbeats."""
    logging.info("Heartbeat monitor started.")
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        current_time = time.time()
        timeout_threshold = current_time - (HEARTBEAT_INTERVAL * HEARTBEAT_TIMEOUT_FACTOR)

        # Check for timeouts first
        timed_out_clients = []
        with clients_lock:
            # Check for clients who haven't sent anything recently
            for nickname, last_active_time in list(last_activity.items()):
                 if last_active_time < timeout_threshold:
                    logging.warning(f"Client {nickname} timed out (last activity: {datetime.fromtimestamp(last_active_time)}).")
                    timed_out_clients.append(nickname)
                    # Don't remove here, do it after iterating

            # Send heartbeat probes to remaining clients
            disconnected_on_heartbeat = []
            for nickname, conn in clients.items():
                if nickname in timed_out_clients:
                    continue # Already marked for removal
                try:
                    # Send a simple probe expecting an 'H' response from client
                    conn.sendall(b'H')
                    logging.debug(f"Sent heartbeat probe to {nickname}")
                except Exception as e:
                    logging.warning(f"Heartbeat probe failed for {nickname}: {e}. Marking for removal.")
                    disconnected_on_heartbeat.append(nickname)

        # Cleanup disconnected clients outside the main loop
        all_to_remove = set(timed_out_clients + disconnected_on_heartbeat)
        if all_to_remove:
            logging.info(f"Clients to remove due to timeout or heartbeat failure: {all_to_remove}")
            for nickname in all_to_remove:
                # Cleanup function handles lock and broadcast
                cleanup_client(nickname)


class VPNServer:
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        try:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # Allow TLS 1.2 and higher
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Recommended security settings
            self.context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
            self.context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            logging.info("SSL context created and certificate loaded.")
        except FileNotFoundError:
            logging.error(f"Server certificate or key file not found ({SERVER_CERT}, {SERVER_KEY}). Please generate them.")
            raise
        except ssl.SSLError as e:
             logging.error(f"SSL Error loading certificate/key: {e}")
             raise

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False


    def client_handler(self, conn, addr):
        """Handles communication with a single client."""
        nickname = None
        client_ip, client_port = addr
        logging.info(f"Incoming connection from {client_ip}:{client_port}")

        try:
            # Initial handshake: Receive nickname
            conn.settimeout(30) # Timeout for initial handshake
            name_len_byte = conn.recv(1)
            if not name_len_byte:
                 logging.warning(f"Connection from {addr} closed before sending nickname length.")
                 return # Client disconnected immediately
            name_len = int.from_bytes(name_len_byte, 'big')

            if name_len == 0 or name_len > 32: # Basic validation
                logging.warning(f"Invalid nickname length ({name_len}) from {addr}. Closing connection.")
                # Maybe send an error message?
                conn.close()
                return

            nickname = recvall(conn, name_len).decode('utf-8', errors='ignore')
            logging.info(f"Received nickname '{nickname}' from {addr}")

            # Check nickname validity/uniqueness
            with clients_lock:
                if not nickname or nickname in clients:
                    error_msg = f"Nickname '{nickname}' is invalid or already in use.".encode('utf-8')
                    logging.warning(f"Nickname conflict or invalid nickname for {nickname} from {addr}.")
                    try:
                         # Send 'E' for Error message
                         conn.sendall(b'E' + len(error_msg).to_bytes(2, 'big') + error_msg)
                    except Exception as send_err:
                         logging.error(f"Could not send nickname error to {addr}: {send_err}")
                    conn.close()
                    return

                # Add client to active list
                logging.info(f"Client {nickname}@{addr} accepted.")
                clients[nickname] = conn
                client_addresses[nickname] = addr
                last_activity[nickname] = time.time() # Initial activity timestamp

            # Set regular communication timeout
            conn.settimeout(TIMEOUT) # Use the main timeout for operations

            # Send initial user list to the new client *and* broadcast to others
            broadcast_user_list()

            # Main message loop
            while self.running:
                try:
                    header = conn.recv(1) # Read message type
                    if not header:
                        logging.info(f"Client {nickname} disconnected gracefully (recv returned empty).")
                        break # Connection closed by client

                    msg_type = header.decode('ascii')
                    current_time = time.time()

                    # Update activity timestamp on *any* valid message from client
                    with clients_lock:
                        if nickname in last_activity: # Check if client is still considered active
                             last_activity[nickname] = current_time
                        else:
                             logging.warning(f"Received message type '{msg_type}' from {nickname} who is no longer in activity list. Closing.")
                             break # Client was likely cleaned up by heartbeat monitor

                    logging.debug(f"Received header '{msg_type}' from {nickname}")

                    if msg_type == 'M':  # Message routing
                        msg_len = int.from_bytes(recvall(conn, 2), 'big')
                        raw_data = recvall(conn, msg_len)
                        message_content = raw_data.decode('utf-8', errors='ignore')
                        logging.info(f"[{nickname}] Msg received: {message_content[:100]}...") # Log truncated msg

                        try:
                            recipient, content = message_content.split(":", 1)
                        except ValueError:
                            logging.warning(f"[{nickname}] Sent malformed message (no ':'): {message_content[:100]}")
                            # Optionally send error back to sender
                            error_msg = b"Malformed message. Use 'recipient:message'."
                            conn.sendall(b'M' + len(error_msg).to_bytes(2, 'big') + error_msg) # Send as a normal message
                            continue

                        with clients_lock:
                            if recipient in clients:
                                try:
                                    payload = f"{nickname}:{content}".encode('utf-8')
                                    clients[recipient].sendall(b'M' + len(payload).to_bytes(2, 'big') + payload)
                                    logging.info(f"Relayed message from {nickname} to {recipient}")
                                except Exception as send_err:
                                     logging.error(f"Failed to relay message from {nickname} to {recipient}: {send_err}")
                                     # Notify sender?
                                     error_msg = f"Failed to send message to {recipient}.".encode('utf-8')
                                     conn.sendall(b'M' + len(error_msg).to_bytes(2, 'big') + error_msg)
                                     # Consider if recipient should be disconnected if send fails repeatedly
                            else:
                                error_msg = f"Recipient '{recipient}' not found.".encode('utf-8')
                                conn.sendall(b'M' + len(error_msg).to_bytes(2, 'big') + error_msg)
                                logging.warning(f"[{nickname}] tried to send message to unknown user: {recipient}")

                    elif msg_type == 'F':  # File transfer routing
                        recipient_len = int.from_bytes(recvall(conn, 1), 'big')
                        recipient = recvall(conn, recipient_len).decode('utf-8')

                        filename_len = int.from_bytes(recvall(conn, 1), 'big')
                        filename = recvall(conn, filename_len).decode('utf-8', errors='ignore') # Be robust with filenames

                        filesize = int.from_bytes(recvall(conn, 4), 'big')

                        # Basic size check (e.g., max 100MB)
                        MAX_FILE_SIZE = 100 * 1024 * 1024
                        if filesize > MAX_FILE_SIZE:
                             logging.warning(f"[{nickname}] attempted to send oversized file '{filename}' ({filesize} bytes) to {recipient}. Rejecting.")
                             error_msg = f"File '{filename}' is too large (max {MAX_FILE_SIZE // 1024 // 1024}MB).".encode('utf-8')
                             conn.sendall(b'M' + len(error_msg).to_bytes(2, 'big') + error_msg)
                             # Need to consume the file data the client is sending to avoid blocking
                             try:
                                 _ = recvall(conn, filesize) # Read and discard
                             except ConnectionError:
                                 logging.warning(f"Connection error while discarding oversized file data from {nickname}")
                                 break # Exit handler on connection error
                             continue # Go to next message loop iteration


                        logging.info(f"[{nickname}] initiating file transfer '{filename}' ({filesize} bytes) to {recipient}")

                        with clients_lock:
                            if recipient in clients:
                                dest_conn = clients[recipient]
                                try:
                                    # Construct file header for recipient
                                    sender_bytes = nickname.encode('utf-8')
                                    filename_bytes = filename.encode('utf-8')
                                    file_header = (
                                        b'F' +
                                        len(sender_bytes).to_bytes(1, 'big') + sender_bytes +
                                        len(filename_bytes).to_bytes(1, 'big') + filename_bytes +
                                        filesize.to_bytes(4, 'big')
                                    )
                                    dest_conn.sendall(file_header)
                                    logging.debug(f"Sent file header for '{filename}' to {recipient}")

                                    # Relay file data in chunks
                                    bytes_sent = 0
                                    while bytes_sent < filesize:
                                        chunk_size = min(BUFFER_SIZE, filesize - bytes_sent)
                                        file_chunk = recvall(conn, chunk_size) # Read chunk from sender
                                        dest_conn.sendall(file_chunk)          # Forward chunk to receiver
                                        bytes_sent += len(file_chunk)
                                        # logging.debug(f"Relayed {bytes_sent}/{filesize} bytes of '{filename}' from {nickname} to {recipient}")

                                    logging.info(f"Successfully relayed file '{filename}' ({filesize} bytes) from {nickname} to {recipient}")

                                except Exception as relay_err:
                                    logging.error(f"Error relaying file from {nickname} to {recipient}: {relay_err}")
                                    # Need to consume any remaining data sender might send
                                    remaining_bytes = filesize - bytes_sent
                                    if remaining_bytes > 0:
                                        try:
                                             _ = recvall(conn, remaining_bytes)
                                             logging.debug(f"Discarded {remaining_bytes} remaining file bytes from {nickname} after relay error.")
                                        except ConnectionError:
                                             logging.warning(f"Connection error while discarding remaining file data from {nickname}")
                                             break # Exit handler on connection error

                                    # Notify sender of failure
                                    error_msg = f"Failed to send file to {recipient}.".encode('utf-8')
                                    try:
                                        conn.sendall(b'M' + len(error_msg).to_bytes(2, 'big') + error_msg)
                                    except Exception:
                                        logging.warning(f"Could not notify {nickname} about file relay failure.")


                            else:
                                logging.warning(f"[{nickname}] tried to send file to unknown user: {recipient}")
                                # Consume the file data the client is sending
                                try:
                                    _ = recvall(conn, filesize) # Read and discard
                                    logging.debug(f"Discarded {filesize} bytes from {nickname} for file to unknown user {recipient}")
                                except ConnectionError:
                                     logging.warning(f"Connection error while discarding file data from {nickname} for unknown user {recipient}")
                                     break # Exit handler on connection error
                                # Notify sender
                                error_msg = f"Recipient '{recipient}' not found.".encode('utf-8')
                                conn.sendall(b'M' + len(error_msg).to_bytes(2, 'big') + error_msg)


                    elif msg_type == 'H':  # Heartbeat response from client
                        # Activity already updated at the start of the loop
                        logging.debug(f"Received heartbeat response from {nickname}")
                        # No further action needed here, the timestamp update is enough

                    else:
                        logging.warning(f"[{nickname}] Sent unknown message type: {msg_type}")
                        # Consider disconnecting client for protocol violation

                except socket.timeout:
                    logging.warning(f"Socket timeout waiting for message from {nickname}. Checking activity...")
                    # Heartbeat monitor will handle actual timeout based on last_activity
                    continue # Continue loop, maybe client will send something later
                except ssl.SSLError as e:
                     # Handle specific SSL errors if needed, e.g., decryption failed
                     logging.error(f"SSL Error with {nickname}@{addr}: {e}")
                     break
                except ConnectionError as e:
                    logging.info(f"ConnectionError with {nickname}@{addr}: {e}. Client likely disconnected.")
                    break # Exit loop for this client
                except Exception as e:
                    logging.error(f"Unhandled error with {nickname}@{addr}: {e}", exc_info=True) # Log stack trace
                    break # Assume connection is unstable

        except Exception as e:
            # Catch errors during initial handshake too
            logging.error(f"Error during initial connection phase with {addr}: {e}", exc_info=True)
        finally:
            # Ensure client is cleaned up regardless of how the handler exits
            logging.info(f"Closing connection handler for {nickname or 'unknown'} from {addr}")
            if nickname:
                cleanup_client(nickname) # Use the cleanup function
            else:
                # If nickname was never assigned, just close the raw connection
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                finally:
                    try:
                        conn.close()
                    except OSError: pass
                logging.info(f"Closed connection for unnamed client from {addr}")


    def start(self):
        """Binds the server socket and starts listening for connections."""
        if self.running:
            logging.warning("Server start() called but already running.")
            return

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logging.info(f"TLS VPN Server started on {self.host}:{self.port}")
            print(f"[+] TLS VPN Server started on {self.host}:{self.port}")

            # Start heartbeat monitor thread
            self.heartbeat_thread = threading.Thread(target=heartbeat_monitor, daemon=True)
            self.heartbeat_thread.start()

            while self.running:
                try:
                    raw_sock, addr = self.server_socket.accept()
                    # Wrap socket immediately with TLS
                    conn = self.context.wrap_socket(raw_sock, server_side=True)
                    logging.debug(f"Accepted connection from {addr}, starting client handler thread.")
                    # Start client handler in a separate thread
                    client_thread = threading.Thread(target=self.client_handler, args=(conn, addr), daemon=True)
                    client_thread.start()
                except ssl.SSLError as e:
                    logging.error(f"SSL Error during connection accept/wrap: {e}")
                    # Close the raw socket if wrapping failed
                    if 'raw_sock' in locals() and raw_sock:
                        raw_sock.close()
                except OSError as e:
                     if self.running: # Only log error if we weren't intending to stop
                         logging.error(f"Socket accept error: {e}")
                     else: # Expected error during shutdown
                         logging.info("Server socket closed.")
                     break # Exit accept loop
                except Exception as e:
                     logging.error(f"Unexpected error in accept loop: {e}", exc_info=True)


        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt received, shutting down server...")
            print("\n[!] Shutting down server...")
        except Exception as e:
            logging.error(f"Server startup or main loop error: {e}", exc_info=True)
            print(f"[!] Server error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stops the server and cleans up resources."""
        if not self.running:
            return
        self.running = False
        logging.info("Stopping server...")

        # Close server socket to stop accepting new connections
        try:
            self.server_socket.close()
        except Exception as e:
            logging.error(f"Error closing server socket: {e}")

        # Close all active client connections
        with clients_lock:
            logging.info(f"Closing {len(clients)} client connections...")
            for nickname, conn in list(clients.items()):
                 try:
                     conn.shutdown(socket.SHUT_RDWR)
                 except OSError: pass # Ignore errors if already closed
                 finally:
                     try:
                         conn.close()
                     except OSError: pass # Ignore errors if already closed
            clients.clear()
            client_addresses.clear()
            last_activity.clear()

        logging.info("Server shutdown complete.")


if __name__ == "__main__":
    # Ensure certs exist before starting
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print(f"Error: Server certificate ({SERVER_CERT}) or key ({SERVER_KEY}) not found.")
        print("Please generate them using OpenSSL:")
        print("openssl req -new -x509 -days 365 -nodes -out server_cert.pem -keyout server_key.pem")
    else:
        server = VPNServer()
        server.start()