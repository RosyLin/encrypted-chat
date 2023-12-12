# EncryptedIM: Encrypted Instant Messenger

## Overview
EncryptedIM is a network programming project that features an encrypted instant messenger system. It is composed of two main components:

1. **Server (`server.py`)**: A single instance that handles incoming messages from clients and broadcasts them to all other connected clients (excluding the sender). This facilitates a group chat environment similar to IRC. The server supports dynamic joining and leaving of clients.

2. **Clients (`client.py`)**: Multiple instances can be run, each connecting to the server. Clients are responsible for sending messages to the server and displaying received messages from other clients.

## Communication
- **Protocol**: TCP sockets are used for communication between clients and the server.
- **Encryption**: Messages and nicknames are encrypted using an encrypt-then-MAC scheme. This includes AES-256 in CBC mode for encryption and an HMAC backed by SHA-256 for message authentication.

## EncryptedIM Client Functionality
The `client.py` script performs the following tasks:

1. **Message Sending**: Reads user input from standard input and sends it to the EncryptedIM server.
2. **Message Receiving**: Listens to the network socket connected to the server, receives messages, and displays them to standard output.

### Message Transmission Protocol
When a client sends a message, it transmits the following data to the server:
1. **Length of JSON Object**: A 4-byte unsigned integer in network-byte order, indicating the length of the following JSON object.
2. **JSON Object**: Contains:
   - `nick`: Sender's nickname/username.
   - `message`: The message text (e.g., "Hello World").
   - `date`: Timestamp of when the message was sent, in seconds since the epoch (January 1, 1970).

## EncryptedIM Server Functionality
The `server.py` script is responsible for:
1. **Connection Management**: Waits for and manages connections from clients, accommodating clients joining or leaving at any time.
2. **Message Broadcasting**: Upon receiving a message from a client, it forwards the message to all other connected clients, excluding the sender.
