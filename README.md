# 🔑 SSH Manager

A secure SSH connection manager application with a beautiful UI.

## ✨ Features

- **📜 My Hosts** - View all your saved SSH connections
- **🔧 Connect** - One-click SSH connection to any host
- **🔄 Test** - Test connection status before connecting
- **➕ Add Host** - Easy add new SSH hosts with username, port, and key
- **🗑️ Delete** - Remove unused hosts
- **⚙️ Settings** - Manage encryption key and configuration

## 🔒 Security Features

- **Fernet encryption** - All sensitive data encrypted (username, host, key_file, password)
- **Secure local storage** - Keys stored in `~/.ssh_manager/` with restricted permissions
- **No API keys exposed** - Local-only storage
- **No data sent to cloud** - Everything stays on your machine

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- SSH client installed

### Installation

```bash
# Clone the repository
git clone https://github.com/kkmok/ssh-manager.git
cd ssh-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run ssh_manager.py --server.port 8502
```

### Usage
1. Open http://localhost:8502 in your browser
2. Go to "Add Host" tab to add your SSH connections
3. Enter name, hostname, username, port, and optional SSH key file path
4. Click "Save Host"
5. Use "My Hosts" tab to test connections or connect to hosts

## 📂 Project Structure

```
ssh_manager/
├── ssh_manager.py      # Main application
├── config/
│   └── hosts.json     # Encrypted hosts storage
├── requirements.txt   # Dependencies
└── README.md
```

## ⚙️ Configuration

SSH Manager stores your encrypted hosts in `~/.ssh_manager/`:
- `hosts.json` - Encrypted host data
- `encryption.key` - Encryption key (protected with 0600 permissions)

## 🔧 Settings

### Regenerate Encryption Key
If you lose your encryption key or want to rotate it, use the "Regenerate Encryption Key" option in Settings. Note: This will require you to re-add all hosts since they'll no longer be decryptable.

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - See LICENSE file for details.

## 💬 Support

For questions or issues:
- Open an issue on GitHub

---

**Built with ❤️ using Streamlit and Paramiko**
