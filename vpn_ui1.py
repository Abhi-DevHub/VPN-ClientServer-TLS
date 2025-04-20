# vpn_client_st.py
import streamlit as st
import socket
import ssl
import threading
import os
import time
from datetime import datetime
import queue # For thread-safe communication

# --- Configuration ---
DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_SERVER_PORT = 8443
RECEIVE_BUFFER_SIZE = 4096
RECEIVED_FILES_DIR = "vpn_received_files"

# --- Helper Functions ---
def recvall(sock, size):
    """Receives exactly 'size' bytes from the socket."""
    data = b''
    while len(data) < size:
        try:
            chunk = sock.recv(min(RECEIVE_BUFFER_SIZE, size - len(data)))
            if not chunk:
                raise ConnectionError("Server disconnected")
        except socket.timeout:
            time.sleep(0.1) # Small delay before retry
            continue
        except ssl.SSLWantReadError:
             time.sleep(0.1)
             continue
        except OSError as e:
             raise ConnectionError(f"Socket error during recvall: {e}")
        data += chunk
    return data

# --- Network Receiver Thread ---
def handle_receive(conn, stop_event, ui_queue):
    """Runs in a background thread to receive data from the server."""
    try:
        while not stop_event.is_set():
            try:
                # Use a short timeout for recv(1) to allow checking stop_event periodically
                conn.settimeout(1.0)
                header = conn.recv(1)
                if not header:
                    ui_queue.put(("disconnect", "Server closed connection."))
                    break

                msg_type = header.decode('ascii')

                if msg_type == 'M':  # Message from server or another user
                    msg_len = int.from_bytes(recvall(conn, 2), 'big')
                    msg_bytes = recvall(conn, msg_len)
                    try:
                        msg = msg_bytes.decode('utf-8')
                        ui_queue.put(("message", msg))
                    except UnicodeDecodeError:
                         ui_queue.put(("message", f"[Received undecodable message: {msg_bytes}]"))

                elif msg_type == 'F':  # File incoming
                    sender_len = int.from_bytes(recvall(conn, 1), 'big')
                    sender = recvall(conn, sender_len).decode('utf-8')

                    filename_len = int.from_bytes(recvall(conn, 1), 'big')
                    filename = recvall(conn, filename_len).decode('utf-8', errors='ignore') # Be robust

                    filesize = int.from_bytes(recvall(conn, 4), 'big')

                    os.makedirs(RECEIVED_FILES_DIR, exist_ok=True)
                    safe_filename = filename.replace('/', '_').replace('\\', '_').replace('..', '')
                    save_path = os.path.join(RECEIVED_FILES_DIR, f"from_{sender}_{safe_filename}")

                    bytes_received = 0
                    try:
                        with open(save_path, "wb") as f:
                            while bytes_received < filesize:
                                chunk_size = min(RECEIVE_BUFFER_SIZE, filesize - bytes_received)
                                file_chunk = recvall(conn, chunk_size)
                                f.write(file_chunk)
                                bytes_received += len(file_chunk)
                        ui_queue.put(("file", f"Received '{filename}' ({filesize} bytes) from {sender}. Saved to '{save_path}'"))
                    except Exception as e:
                         ui_queue.put(("error", f"Error saving file '{filename}' from {sender}: {e}"))
                         remaining = filesize - bytes_received
                         if remaining > 0:
                             try: _ = recvall(conn, remaining)
                             except Exception as consume_err:
                                 ui_queue.put(("error", f"Error consuming remaining file data after save failure: {consume_err}"))


                elif msg_type == 'U': # User list update
                    list_len = int.from_bytes(recvall(conn, 2), 'big')
                    list_str = recvall(conn, list_len).decode('utf-8')
                    users = list_str.split(',') if list_str else []
                    ui_queue.put(("users", users))

                elif msg_type == 'H': # Heartbeat probe from server
                    try:
                        conn.sendall(b'H')
                        ui_queue.put(("status", "Heartbeat response sent to server."))
                    except Exception as e:
                        ui_queue.put(("error", f"Failed to send heartbeat response: {e}"))

                elif msg_type == 'E': # Error message directly from server
                    error_len = int.from_bytes(recvall(conn, 2), 'big')
                    error_msg = recvall(conn, error_len).decode('utf-8')
                    ui_queue.put(("error", f"Server Error: {error_msg}"))
                    if "Nickname" in error_msg and "in use" in error_msg:
                        ui_queue.put(("disconnect", f"Server rejected nickname."))
                        break

            except socket.timeout:
                continue # Ignore timeout on the initial recv(1), just loop again
            except ssl.SSLError as e:
                 ui_queue.put(("error", f"SSL Error: {e}"))
                 ui_queue.put(("disconnect", f"SSL Error: {e}"))
                 break
            except ConnectionError as e:
                ui_queue.put(("disconnect", f"Connection lost: {e}"))
                break
            except Exception as e:
                ui_queue.put(("error", f"Receiver Error: {e}"))
                ui_queue.put(("disconnect", f"Unexpected receiver error: {e}"))
                break

    except Exception as outer_e:
         ui_queue.put(("error", f"Receiver thread failed unexpectedly: {outer_e}"))
         ui_queue.put(("disconnect", "Receiver thread failure."))
    finally:
        print("Receiver thread finished.")


# --- Streamlit UI ---

st.set_page_config(layout="wide")
st.title("🔒 TLS VPN Client") # Restored original title

# Initialize session state variables only once
if 'initialized' not in st.session_state:
    st.session_state.initialized = True
    st.session_state.connected = False
    st.session_state.conn = None
    st.session_state.nickname = ""
    st.session_state.server_ip = DEFAULT_SERVER_IP
    st.session_state.server_port = DEFAULT_SERVER_PORT
    st.session_state.receiver_thread = None
    st.session_state.stop_event = None
    st.session_state.ui_queue = queue.Queue()
    st.session_state.messages = []
    st.session_state.users = []
    st.session_state.file_notifications = []
    st.session_state.error_messages = []
    st.session_state.status_messages = []
    st.session_state.last_server_activity = None
    print("Session State Initialized")


# --- UI Helper to process queue ---
def process_ui_queue():
    """Process messages from the receiver thread queue and update state."""
    refreshed = False
    while not st.session_state.ui_queue.empty():
        msg_type, data = st.session_state.ui_queue.get()
        now = datetime.now().strftime("%H:%M:%S")
        st.session_state.last_server_activity = time.time() # Update activity on any received message
        refreshed = True

        if msg_type == "message":
            st.session_state.messages.append(f"[{now}] {data}")
        elif msg_type == "file":
            st.session_state.file_notifications.append(f"[{now}] {data}")
        elif msg_type == "users":
            new_users = sorted(list(set(data)))
            if new_users != st.session_state.users:
                 st.session_state.users = new_users
                 st.session_state.status_messages.append(f"[{now}] User list updated.")
        elif msg_type == "error":
            st.session_state.error_messages.append(f"[{now}] {data}")
        elif msg_type == "status":
            st.session_state.status_messages.append(f"[{now}] {data}")
        elif msg_type == "disconnect":
            if st.session_state.connected:
                 st.session_state.error_messages.append(f"[{now}] Disconnected: {data}")
                 st.toast(f"Disconnected: {data}", icon="⚠️")
                 st.session_state.connected = False
                 if st.session_state.stop_event:
                     st.session_state.stop_event.set()
                 if st.session_state.conn:
                     try: st.session_state.conn.close()
                     except Exception: pass
                 st.session_state.conn = None
                 st.session_state.users = []

        # Limit message history sizes
        st.session_state.messages = st.session_state.messages[-100:]
        st.session_state.file_notifications = st.session_state.file_notifications[-50:]
        st.session_state.error_messages = st.session_state.error_messages[-50:]
        st.session_state.status_messages = st.session_state.status_messages[-50:]

    return refreshed # Return True if any messages were processed

# --- Connection Panel ---
with st.sidebar:
    st.header("Connection")
    if not st.session_state.connected:
        st.session_state.server_ip = st.text_input("Server IP", value=st.session_state.server_ip, key="srv_ip_input")
        st.session_state.server_port = st.number_input("Server Port", value=st.session_state.server_port, min_value=1, max_value=65535, key="srv_port_input")
        st.session_state.nickname = st.text_input("Nickname", value=st.session_state.nickname, max_chars=32, key="nick_input")

        # --- Verification UI and warning removed ---

        connect_button = st.button("Connect", key="connect_btn")

        if connect_button:
            if not st.session_state.nickname:
                st.error("Nickname cannot be empty.")
            else:
                with st.spinner("Connecting..."):
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE

                        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        raw_sock.settimeout(10)

                        conn = context.wrap_socket(raw_sock)
                        conn.connect((st.session_state.server_ip, st.session_state.server_port))
                        conn.settimeout(None)

                        nick_bytes = st.session_state.nickname.encode('utf-8')
                        conn.sendall(len(nick_bytes).to_bytes(1, 'big') + nick_bytes)

                        st.session_state.conn = conn
                        st.session_state.connected = True
                        st.session_state.last_server_activity = time.time()

                        st.session_state.messages = []
                        st.session_state.users = []
                        st.session_state.file_notifications = []
                        st.session_state.error_messages = ["Connection successful."]
                        st.session_state.status_messages = [f"[{datetime.now().strftime('%H:%M:%S')}] Connected to server."]
                        while not st.session_state.ui_queue.empty():
                             try: st.session_state.ui_queue.get_nowait()
                             except queue.Empty: break

                        st.session_state.stop_event = threading.Event()
                        st.session_state.receiver_thread = threading.Thread(
                            target=handle_receive,
                            args=(st.session_state.conn, st.session_state.stop_event, st.session_state.ui_queue),
                            daemon=True
                        )
                        st.session_state.receiver_thread.start()
                        st.success(f"Connected as {st.session_state.nickname}")
                        st.rerun()

                    except socket.timeout:
                        st.error("Connection timed out.")
                    except ConnectionRefusedError:
                         st.error("Connection refused. Is the server running?")
                    except ssl.SSLError as e:
                        st.error(f"SSL Error during connection: {e}")
                        st.exception(e)
                    except Exception as e:
                        st.error(f"Connection failed: {e}")
                        st.exception(e)
                        if 'conn' in locals() and conn:
                           try: conn.close()
                           except: pass
                        if st.session_state.conn:
                            try: st.session_state.conn.close()
                            except: pass
                        st.session_state.conn = None
                        st.session_state.connected = False

    else: # If connected
        st.success(f"Connected as **{st.session_state.nickname}**")
        st.write(f"Server: {st.session_state.server_ip}:{st.session_state.server_port}")
        if st.session_state.last_server_activity:
             last_active_str = datetime.fromtimestamp(st.session_state.last_server_activity).strftime('%Y-%m-%d %H:%M:%S')
             st.caption(f"Last server activity: {last_active_str}")
        else:
             st.caption("No activity received from server yet.")

        if st.button("🔄 Refresh Display", key="refresh_btn"):
            processed = process_ui_queue()
            if processed: st.toast("Display updated.", icon="✅")
            else: st.toast("No new updates.", icon="🤷")
            st.rerun()

        if st.button("Disconnect", key="disconnect_btn"):
            st.session_state.status_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] Disconnecting...")
            if st.session_state.conn:
                try: st.session_state.conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                finally:
                    try: st.session_state.conn.close()
                    except OSError: pass

            if st.session_state.stop_event:
                st.session_state.stop_event.set()

            st.session_state.connected = False
            st.session_state.conn = None
            st.session_state.users = []
            st.info("Disconnected.")
            time.sleep(0.5)
            st.rerun()

# --- Main Processing Logic ---
needs_rerun = False
if st.session_state.connected:
    if process_ui_queue():
        needs_rerun = True

# --- Main Area (only shown when connected) ---
if st.session_state.connected:
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Send Data")
        action = st.radio("Action", ["Send Message", "Send File"], horizontal=True, label_visibility="collapsed", key="action_radio")

        recipient_options = [u for u in st.session_state.users if u != st.session_state.nickname]
        if not recipient_options:
            st.caption("No other users connected to send to.")
            selected_recipient = None
        else:
            selected_recipient = st.selectbox("Recipient", recipient_options, key="recipient_select")

        if action == "Send Message":
            message_content = st.text_area("Message", height=100, key="msg_input_area")
            send_msg_button = st.button("Send Message", key="send_msg_btn", disabled=(not selected_recipient or not message_content))

            if send_msg_button and selected_recipient and message_content:
                full_msg = f"{selected_recipient}:{message_content}".encode('utf-8')
                try:
                    with st.spinner("Sending message..."):
                        st.session_state.conn.sendall(b'M' + len(full_msg).to_bytes(2, 'big') + full_msg)
                        st.session_state.status_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] Message sent to {selected_recipient}")
                        st.toast("Message sent!")
                        needs_rerun = True
                except Exception as e:
                    st.error(f"Failed to send message: {e}")
                    st.session_state.error_messages.append(f"Message send failed: {e}")
                    st.session_state.connected = False
                    needs_rerun = True

        elif action == "Send File":
            uploaded_file = st.file_uploader("Choose a file", key="file_uploader")
            send_file_button = st.button("Send File", key="send_file_btn", disabled=(not selected_recipient or not uploaded_file))

            if send_file_button and selected_recipient and uploaded_file:
                 with st.spinner(f"Sending {uploaded_file.name} to {selected_recipient}..."):
                     try:
                         file_bytes = uploaded_file.getvalue()
                         filename = uploaded_file.name
                         filesize = len(file_bytes)

                         MAX_FILE_SIZE = 100 * 1024 * 1024
                         if filesize > MAX_FILE_SIZE:
                             st.error(f"File is too large (max {MAX_FILE_SIZE // 1024 // 1024}MB).")
                         elif filesize == 0:
                              st.warning("Cannot send an empty file.")
                         else:
                             recipient_bytes = selected_recipient.encode('utf-8')
                             filename_bytes = filename.encode('utf-8')

                             header = (
                                 b'F' +
                                 len(recipient_bytes).to_bytes(1, 'big') + recipient_bytes +
                                 len(filename_bytes).to_bytes(1, 'big') + filename_bytes +
                                 filesize.to_bytes(4, 'big')
                             )
                             st.session_state.conn.sendall(header + file_bytes)
                             st.session_state.status_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] Sent '{filename}' ({filesize} bytes) to {selected_recipient}")
                             st.toast("File sent!")
                             needs_rerun = True

                     except Exception as e:
                         st.error(f"Failed to send file: {e}")
                         st.session_state.error_messages.append(f"File send failed: {e}")
                         st.session_state.connected = False
                         needs_rerun = True

        st.divider()

        tab_msg, tab_files, tab_status, tab_errors = st.tabs(["Messages", "File Transfers", "Status Log", "Errors"])

        with tab_msg:
            st.subheader("Messages")
            st.text_area("Received Messages", value="\n".join(st.session_state.messages), height=300, key="msg_display", disabled=True)

        with tab_files:
            st.subheader("File Transfers")
            st.write(f"Files are saved to: `{os.path.abspath(RECEIVED_FILES_DIR)}`")
            st.text_area("Notifications", value="\n".join(st.session_state.file_notifications), height=300, key="file_display", disabled=True)

        with tab_status:
             st.subheader("Status Log")
             st.text_area("Log", value="\n".join(st.session_state.status_messages), height=300, key="status_display", disabled=True)

        with tab_errors:
            st.subheader("Error Log")
            if st.session_state.error_messages:
                 st.text_area("Errors", value="\n".join(st.session_state.error_messages), height=300, key="error_display", disabled=True)
            else:
                 st.caption("No errors logged.")

    with col2:
        st.subheader("Connected Users")
        if st.session_state.users:
            users_display = []
            for user in st.session_state.users:
                if user == st.session_state.nickname:
                    users_display.append(f"**{user} (You)**")
                else:
                    users_display.append(user)
            st.markdown("\n".join(f"- {u}" for u in users_display))
        else:
            st.caption("Waiting for user list from server...")
            if st.session_state.connected and not st.session_state.users:
                 st.caption("(If this persists, try refreshing or check server connection)")

# --- Cleanup Logic ---
if not st.session_state.connected and st.session_state.receiver_thread is not None:
     if st.session_state.stop_event and not st.session_state.stop_event.is_set():
         st.session_state.stop_event.set()
         print("Signaled receiver thread to stop due to disconnection.")
     st.session_state.receiver_thread = None
     st.session_state.stop_event = None
     st.session_state.conn = None
     print("Cleaned up receiver thread resources after disconnect state detected.")

# --- Final Rerun Check ---
if needs_rerun:
    st.rerun()