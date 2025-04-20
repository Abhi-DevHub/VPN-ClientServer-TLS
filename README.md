
# 🔐 VPN-ClientServer-TLS

A fully secure Python-based VPN with **TLS encryption**, **multi-client communication**, **message/file transfer**, and a **Streamlit UI** for real-time control and monitoring.

---

## 🚀 Features

- ✅ TLS-secured communication with client/server certificates  
- 👥 Multi-client support with unique nicknames  
- 💬 Broadcast and private messaging  
- 📁 Secure file transfer with binary-safe communication  
- 🔁 Heartbeat mechanism to auto-disconnect idle clients  
- 📊 Real-time logging and monitoring via Streamlit  
- 🧠 Simple and extensible codebase  

---

## 🗂️ Project Structure

```plaintext
VPN-ClientServer-TLS/
├── ca_cert.pem             # Certificate authority (optional)
├── client_cert.pem         # Client TLS certificate
├── client_key.pem          # Client TLS private key
├── server_key_1.pem        # (Unused/backup key)
├── server_key.pem          # Server TLS private key
├── vpn_client_tls.py       # TLS-enabled client script
├── vpn_server_tls.py       # TLS-enabled server script
├── vpn_ui1.py              # Streamlit UI for managing client/server
├── vpn_client_tls.log      # Client log (auto-generated)
├── README.md               # You're here!
```

---

## 💻 Requirements

- Python 3.8 or above
- **Install dependencies**:

```bash
pip install streamlit
```

> 🔒 `ssl` is built-in in Python, no need to install separately.

---

## 📜 TLS Certificate Setup

If not using pre-included certs, generate your own using OpenSSL:

```bash
# Server cert + key
openssl req -new -x509 -days 365 -nodes -out server_cert.pem -keyout server_key.pem

# Client cert + key
openssl req -new -x509 -days 365 -nodes -out client_cert.pem -keyout client_key.pem
```

> ⚠️ Ensure the server and client **trust each other's certificates**.

---

## 🛠️ How to Run

### 1. Start the Server
```bash
python vpn_server_tls.py
```

OR with Streamlit UI:
```bash
streamlit run vpn_ui1.py
```

### 2. Start a Client
```bash
python vpn_client_tls.py
```

---

## 💬 Messaging Syntax

- **Broadcast**: Just type and send your message.  
- **Private**: Use `@username message` to send a private message.

---

## 📁 File Transfer

- Clients can send files securely through the server.
- Files are stored in the same directory under the sender's name.
- Works for all file types (binary-safe).

---

## 🔧 How It Works

- 🔐 **TLS Layer**: The server uses `ssl.wrap_socket()` to securely wrap its socket using its certificate and key. Clients verify the server using its certificate.
- 👥 **Client Registration**: Each client sends a unique nickname upon connection. The server manages a list of active clients.
- 💬 **Communication**: All messages and files are sent through the server. It handles broadcast or private delivery based on message format.
- 🗂 **File Transfer**: Files are read in binary mode and securely relayed from one client to another through the server, preserving integrity.
- 🧠 **Heartbeat Thread**: The server sends periodic pings and disconnects unresponsive or idle clients.
- 📊 **Streamlit UI**: Provides a dashboard to monitor active clients, logs, and control the server directly via web browser.

---

## 🔄 Heartbeat Monitoring

The server automatically pings clients and disconnects idle/inactive users to preserve resources.

---

## 📈 Logging

- Logs are saved as `vpn_client_tls.log`.
- Tracks all message transfers, file transfers, client events, and errors.

---

## ✅ Tested On

- ✅ Windows 10/11  
- ✅ WSL (Ubuntu 20.04)  
- ✅ Python 3.8+ and 3.11+

---

## 📌 To Do

- [ ] Add authentication prompt in UI  
- [ ] Add compression to file transfers  
- [ ] Show file transfer status in GUI  
- [ ] Use public CA for production TLS setup
