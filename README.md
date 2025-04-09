
# 🔌 Python IRC Server

A feature-rich IRC (Internet Relay Chat) server written in Python. This server supports user authentication, registration with invite codes, channel persistence, topics, operator controls, and more!

---

## ✨ Features

- ✅ **User Authentication** with password hashing (bcrypt)
- ✅ **Registration via Invite Codes**
- ✅ **Roles**: Admin, Moderator, and User
- ✅ **Channel Support** with topics and operator (MODE/KICK) controls
- ✅ **Persistent Channels and User Data** (stored in JSON)
- ✅ **Invite Code System** with usage tracking and audit logging
- ✅ **IP and Login Tracking** for registered users

---

## 📦 Requirements

Install the required dependency using:

```bash
pip install bcrypt
```

## 🚀 Runing the Server
```bash
 irc_server.py
```

## 🛡️ Login
/LOGIN yourpassword

## 📝 Register (requires invite code)
/REGISTER yourpassword INVITECODE

## 🧾 Invite Code System
/GENERATE_INVITE 3

## 👥 Roles
Each user has a role in users.json:

- admin: Full control, can generate invites and manage users
- mod: Can manage channels (topics, kicking users)
- user: Regular access to chat and join channels

## 🗂️ Channel Commands
- Join/create channel: /JOIN #channelname
- Set topic: /TOPIC #channelname :New topic here
- Give op: /MODE #channelname +o nick
- Kick user: /KICK #channelname nick

## 🧠 Data Persistence
Data is stored in these JSON files:
- users.json — User accounts, roles, IP addresses, login history
- channels.json — Channels and topics
- generated_invites.json — Invite codes with metadata

## 📁 Example users.json Entry

```json 
{
  "alice": {
    "password": "$2b$12$....",
    "role": "admin",
    "invite_code": "INVITE123",
    "register_date": "2025-04-09T12:34:56",
    "last_login": "2025-04-09T13:00:00",
    "ip_address": "192.168.1.50"
  },
  "John": {
    "password": "$2b$12$....",
    "role": "mod",
    "invite_code": "INVITE123",
    "register_date": "2025-04-09T12:34:56",
    "last_login": "2025-04-09T13:00:00",
    "ip_address": "192.168.1.50"
  },
  "joe": {
    "password": "$2b$12$....",
    "role": "user",
    "invite_code": "INVITE123",
    "register_date": "2025-04-09T12:34:56",
    "last_login": "2025-04-09T13:00:00",
    "ip_address": "192.168.1.50"
  }
}
```

## 📁 Example generated_invites.json Entry
```json 
[
  {
    "code": "admin",
    "usage_count": 1,
    "created_by": "Admin",
    "created_at": "2025-04-09T00:46:52.126370"
  }
]
```

## 📁 Example channels.json Entry
```json 
{
  "#general": {
    "topic": "Welcome to General",
    "operators": [
      "Admin"
    ]
  },
  "#chat": {
    "topic": "Anything open chat",
    "operators": [
      "Admin"
    ]
  }
}
```


## 🔒 Security
- Passwords are stored using bcrypt
- IP address and login time are tracked per user
- Registration is restricted to invite-only

## 💡 Tips
- Only admins can generate invite codes
- Roles are manually editable in users.json
- You can reset channels or users by deleting the respective .json files (use with caution)

