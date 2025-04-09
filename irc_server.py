import socket
import threading
import json
import os
import bcrypt
from datetime import datetime

HOST = '0.0.0.0'
PORT = 6667

clients = {}   # socket -> {'nick': ..., 'channel': ..., 'authenticated': bool, 'role': str}
channels = {}  # channel_name -> { topic: str, users: set(), operators: set() }
users_db = {}  # nick -> {'password': hashed password, 'role': str, 'invite_code': str, 'register_date': str, 'last_login': str, 'ip_address': str}
generated_invites = []  # List of generated invite codes with metadata

CHANNELS_FILE = 'channels.json'
USERS_FILE = 'users.json'
INVITE_CODES_FILE = 'generated_invites.json'


def load_users():
    global users_db
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
            users_db = data.get("users", {})


def load_generated_invites():
    global generated_invites
    if os.path.exists(INVITE_CODES_FILE):
        with open(INVITE_CODES_FILE, 'r') as f:
            generated_invites = json.load(f)


def load_channels():
    if os.path.exists(CHANNELS_FILE):
        with open(CHANNELS_FILE, 'r') as f:
            raw = json.load(f)
            for chan, meta in raw.items():
                channels[chan] = {
                    'topic': meta.get('topic', ''),
                    'users': set(),
                    'operators': set(meta.get('operators', []))
                }


def save_channels():
    data = {
        chan: {
            'topic': info['topic'],
            'operators': list(info['operators'])
        }
        for chan, info in channels.items()
    }
    with open(CHANNELS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def save_users():
    data = {
        'users': users_db
    }
    with open(USERS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def save_generated_invites():
    with open(INVITE_CODES_FILE, 'w') as f:
        json.dump(generated_invites, f, indent=2)


def generate_invite_code(usage_count, created_by):
    invite_code = os.urandom(8).hex().upper()
    created_at = datetime.now().isoformat()

    generated_invites.append({
        "code": invite_code,
        "usage_count": usage_count,
        "created_by": created_by,
        "created_at": created_at
    })
    save_generated_invites()
    return invite_code


def broadcast(channel, message, sender=None):
    for client in channels.get(channel, {}).get('users', []):
        if client != sender:
            try:
                client.sendall(message.encode('utf-8'))
            except:
                pass


def handle_client(client_socket, addr):
    client_socket.sendall(b":server NOTICE AUTH :Welcome\r\n")
    nick = None
    authenticated = False
    current_channel = None
    user_role = None
    user_invite_code = None

    while True:
        try:
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                break

            for line in data.strip().split('\r\n'):
                parts = line.strip().split()
                if not parts:
                    continue

                command = parts[0].upper()

                if command == 'NICK':
                    nick = parts[1]
                    clients[client_socket] = {'nick': nick, 'authenticated': False}
                    client_socket.sendall(f":server NOTICE {nick} :Nickname set to {nick}. Use LOGIN <password> to authenticate.\r\n".encode('utf-8'))

                elif command == 'LOGIN':
                    if not nick:
                        client_socket.sendall(b":server NOTICE * :You must set a nickname first using NICK <name>\r\n")
                        continue

                    if len(parts) < 2:
                        client_socket.sendall(f":server NOTICE {nick} :Usage: LOGIN <password>\r\n".encode('utf-8'))
                        continue

                    password = parts[1]
                    if nick in users_db and bcrypt.checkpw(password.encode('utf-8'), users_db[nick]['password'].encode('utf-8')):
                        clients[client_socket]['authenticated'] = True
                        authenticated = True
                        user_role = users_db[nick]['role']
                        user_invite_code = users_db[nick]['invite_code']
                        users_db[nick]['last_login'] = datetime.now().isoformat()
                        users_db[nick]['ip_address'] = addr[0]  # Store the IP address
                        save_users()
                        client_socket.sendall(f":server 001 {nick} :Authenticated. Welcome!\r\n".encode('utf-8'))
                    else:
                        client_socket.sendall(f":server 464 {nick} :Password incorrect\r\n".encode('utf-8'))
                        client_socket.close()
                        return

                elif command == 'REGISTER':
                    if len(parts) < 3:
                        client_socket.sendall(f":server NOTICE {nick} :Usage: REGISTER <password> <invite_code>\r\n".encode('utf-8'))
                        continue

                    password = parts[1]
                    invite_code = parts[2]

                    # Check if invite code is valid
                    valid_invite = None
                    for invite in generated_invites:
                        if invite['code'] == invite_code and invite['usage_count'] > 0:
                            valid_invite = invite
                            break

                    if valid_invite is None:
                        client_socket.sendall(f":server NOTICE {nick} :Invalid or expired invite code.\r\n".encode('utf-8'))
                        continue

                    if nick in users_db:
                        client_socket.sendall(f":server NOTICE {nick} :Nickname already taken.\r\n".encode('utf-8'))
                        continue

                    # Hash password and register the user
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    users_db[nick] = {
                        'password': hashed_password,
                        'role': 'user',  # Default role is user
                        'invite_code': invite_code,
                        'register_date': datetime.now().isoformat(),
                        'last_login': None,  # No login yet
                        'ip_address': None  # No IP yet
                    }
                    # Reduce the usage count of the invite code
                    valid_invite['usage_count'] -= 1
                    save_generated_invites()
                    save_users()
                    client_socket.sendall(f":server NOTICE {nick} :Registration successful. Please login with /login <password>\r\n".encode('utf-8'))

                elif command == 'GENERATE_INVITE':
                    if len(parts) < 2:
                        client_socket.sendall(f":server NOTICE {nick} :Usage: GENERATE_INVITE <usage_count>\r\n".encode('utf-8'))
                        continue

                    usage_count = int(parts[1])

                    # Only allow admins to generate invites
                    if user_role != 'admin':
                        client_socket.sendall(f":server NOTICE {nick} :Only admins can generate invite codes.\r\n".encode('utf-8'))
                        continue

                    invite_code = generate_invite_code(usage_count, nick)
                    client_socket.sendall(f":server NOTICE {nick} :Invite code {invite_code} generated with {usage_count} uses.\r\n".encode('utf-8'))

                elif command == 'TOPIC' and len(parts) > 2:
                    channel = parts[1]
                    topic = ' '.join(parts[2:]).lstrip(':')

                    # Only admins and mods can set the topic
                    if user_role in ['admin', 'mod'] and nick in channels.get(channel, {}).get('operators', set()):
                        channels[channel]['topic'] = topic
                        broadcast(channel, f":{nick} TOPIC {channel} :{topic}\r\n")
                        save_channels()
                    else:
                        client_socket.sendall(f":server 482 {nick} {channel} :You're not a channel operator\r\n".encode('utf-8'))

                elif command == 'MODE' and len(parts) >= 4:
                    channel = parts[1]
                    mode = parts[2]
                    target = parts[3]
                    if mode == '+o':
                        if user_role in ['admin', 'mod'] and nick in channels.get(channel, {}).get('operators', set()):
                            for sock, info in clients.items():
                                if info.get('nick') == target:
                                    channels[channel]['operators'].add(target)
                                    sock.sendall(f":{nick} MODE {channel} +o {target}\r\n".encode('utf-8'))
                                    save_channels()
                                    break
                        else:
                            client_socket.sendall(f":server 482 {nick} {channel} :You're not a channel operator\r\n".encode('utf-8'))

                elif command == 'KICK' and len(parts) >= 3:
                    channel = parts[1]
                    target = parts[2]
                    if user_role in ['admin', 'mod'] and nick in channels.get(channel, {}).get('operators', set()):
                        for sock, info in clients.items():
                            if info.get('nick') == target:
                                channels[channel]['users'].discard(sock)
                                broadcast(channel, f":{nick} KICK {channel} {target} :Kicked\r\n")
                                sock.sendall(f":{nick} KICK {channel} {target} :Kicked\r\n".encode('utf-8'))
                                break
                    else:
                        client_socket.sendall(f":server 482 {nick} {channel} :You're not a channel operator\r\n".encode('utf-8'))

                elif command == 'PRIVMSG':
                    target = parts[1]
                    message = ' '.join(parts[2:])[1:]
                    if target.startswith('#'):
                        broadcast(target, f":{nick} PRIVMSG {target} :{message}\r\n", client_socket)
                    else:
                        for c, info in clients.items():
                            if info.get('nick') == target:
                                c.sendall(f":{nick} PRIVMSG {target} :{message}\r\n".encode('utf-8'))

                elif command == 'QUIT':
                    client_socket.sendall(b"ERROR :Closing Link\r\n")
                    break

        except Exception as e:
            print(f"Error with {addr}: {e}")
            break

    # Disconnect cleanup
    if current_channel and client_socket in channels.get(current_channel, {}).get('users', set()):
        channels[current_channel]['users'].remove(client_socket)
        broadcast(current_channel, f":{nick} QUIT :Quit\r\n", client_socket)

    if client_socket in clients:
        del clients[client_socket]

    client_socket.close()
    save_channels()
    save_users()
    save_generated_invites()
    print(f"Disconnected {addr}")


def start_server():
    load_users()
    load_generated_invites()
    load_channels()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    print(f"IRC Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()
