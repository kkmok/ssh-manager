#!/usr/bin/env python3
"""
SSH Manager - A secure SSH connection manager application
Manage your SSH hosts, usernames, and keys with a beautiful UI
Security features:
- Sensitive data encryption
- No API keys exposed
- Secure local storage
"""

import os
import json
import paramiko
import streamlit as st
from datetime import datetime
from pathlib import Path
import subprocess
from cryptography.fernet import Fernet
import base64
import re

# Configuration
CONFIG_DIR = Path.home() / ".ssh_manager"
CONFIG_FILE = CONFIG_DIR / "hosts.json"
HISTORY_FILE = CONFIG_DIR / "connection_history.json"
KEY_FILE = CONFIG_DIR / "encryption.key"
IMPORTED_CONFIG = CONFIG_DIR / "imported_ssh_config.json"

# Ensure config directory exists
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Custom CSS
st.markdown("""
<style>
    .main { background-color: #1a1d21; color: #e0e0e0; }
    .stApp { background-color: #1a1d21; }
    .stButton>button { background-color: #2b2f36; color: #e0e0e0; border: 1px solid #4f8aff; border-radius: 8px; }
    .stButton>button:hover { background-color: #4f8aff; color: white; }
    .card { background-color: #2b2f36; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    .host-online { color: #10b981; font-weight: bold; }
    .host-offline { color: #ef4444; font-weight: bold; }
    .ssh-key-icon { color: #f59e0b; }
    .security-badge { background-color: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
    .command-box { background-color: #1a1d21; border: 1px solid #4f8aff; border-radius: 8px; padding: 12px; font-family: monospace; margin: 8px 0; }
</style>
""", unsafe_allow_html=True)

def get_encryption_key():
    """Get or create encryption key"""
    if KEY_FILE.exists():
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        os.chmod(KEY_FILE, 0o600)
        return key

def encrypt_data(data):
    """Encrypt sensitive data"""
    fernet = Fernet(get_encryption_key())
    return base64.b64encode(fernet.encrypt(data.encode())).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if not encrypted_data:
        return None
    try:
        fernet = Fernet(get_encryption_key())
        return fernet.decrypt(base64.b64decode(encrypted_data)).decode()
    except Exception:
        return None

def load_hosts():
    """Load SSH hosts from config file"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return []

def save_hosts(hosts):
    """Save SSH hosts to config file with encryption"""
    encrypted_hosts = []
    for host in hosts:
        encrypted_host = host.copy()
        if host.get('username'):
            encrypted_host['username'] = encrypt_data(host['username'])
        if host.get('host'):
            encrypted_host['host'] = encrypt_data(host['host'])
        if host.get('key_file'):
            encrypted_host['key_file'] = encrypt_data(host['key_file'])
        if host.get('password'):
            encrypted_host['password'] = encrypt_data(host['password'])
        encrypted_hosts.append(encrypted_host)
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(encrypted_hosts, f, indent=2)

def load_history():
    """Load connection history"""
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return {"history": []}

def save_history(history):
    """Save connection history"""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def test_ssh_connection(host_data, timeout=5):
    """Test SSH connection to a host"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        host_addr = decrypt_data(host_data.get('host', '')) or host_data.get('host', 'Unknown')
        user = decrypt_data(host_data.get('username', '')) or host_data.get('username', 'Unknown')
        key_file = decrypt_data(host_data.get('key_file', '')) if host_data.get('key_file') else None
        
        if key_file and os.path.exists(key_file):
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host_addr, username=user, pkey=key, timeout=timeout)
        else:
            ssh.connect(host_addr, username=user, timeout=timeout)
        
        ssh.close()
        return True
    except Exception as e:
        return False

def generate_ssh_command(host_data):
    """Generate SSH command with all options"""
    host_addr = decrypt_data(host_data.get('host', '')) or host_data.get('host', 'Unknown')
    user = decrypt_data(host_data.get('username', '')) or host_data.get('username', 'Unknown')
    port = host_data.get('port', 22)
    key_file = decrypt_data(host_data.get('key_file', '')) if host_data.get('key_file') else None
    
    # Check for port forwarding
    forward_local = host_data.get('forward_local', '')
    forward_remote = host_data.get('forward_remote', '')
    forward_dynamic = host_data.get('forward_dynamic', '')
    
    cmd = "ssh"
    cmd += f" -p {port}"
    cmd += f" {user}@{host_addr}"
    
    if key_file:
        cmd += f" -i {key_file}"
    
    # Port forwarding
    if forward_local:
        cmd += f" -L {forward_local}"
    if forward_remote:
        cmd += f" -R {forward_remote}"
    if forward_dynamic:
        cmd += f" -D {forward_dynamic}"
    
    return cmd

def ssh_connection(host_data, dry_run=False):
    """Initiate SSH connection"""
    host_addr = decrypt_data(host_data.get('host', '')) or host_data.get('host', 'Unknown')
    user = decrypt_data(host_data.get('username', '')) or host_data.get('username', 'Unknown')
    
    cmd = generate_ssh_command(host_data)
    
    if dry_run:
        return cmd
    
    # Add to history
    history = load_history()
    history["history"].insert(0, {
        "name": host_data.get('name', 'Unknown'),
        "host": host_addr,
        "user": user,
        "timestamp": datetime.now().isoformat(),
        "command": cmd
    })
    # Keep only last 50 entries
    history["history"] = history["history"][:50]
    save_history(history)
    
    print(f"Connecting to {host_addr} as {user}...")
    subprocess.run(cmd, shell=True)

def delete_host(index):
    """Delete a host from the list"""
    hosts = load_hosts()
    del hosts[index]
    save_hosts(hosts)
    st.rerun()

def import_ssh_config():
    """Import existing SSH config from ~/.ssh/config"""
    ssh_config_path = Path.home() / ".ssh" / "config"
    if not ssh_config_path.exists():
        return None
    
    hosts = []
    current_host = {}
    
    try:
        with open(ssh_config_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if line.lower().startswith('host '):
                    if current_host:
                        hosts.append(current_host)
                    current_host = {"name": line.split()[1]}
                elif line.lower().startswith('hostname '):
                    current_host['host'] = line.split(' ', 1)[1]
                elif line.lower().startswith('user '):
                    current_host['username'] = line.split(' ', 1)[1]
                elif line.lower().startswith('port '):
                    current_host['port'] = int(line.split()[1])
                elif line.lower().startswith('identityfile '):
                    key_path = line.split(' ', 1)[1].replace('~', str(Path.home()))
                    current_host['key_file'] = key_path
        
        if current_host:
            hosts.append(current_host)
        
        return hosts
    except Exception as e:
        return None

def main():
    st.title("🔑 SSH Manager")
    st.markdown("## Manage your SSH connections securely")
    st.markdown('<span class="security-badge">🔒 Encrypted Storage</span>', unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.header("📊 Statistics")
    hosts = load_hosts()
    st.sidebar.metric("Total Hosts", len(hosts))
    
    # History
    history = load_history()
    st.sidebar.subheader("⚡ Recent Connections")
    if history.get("history"):
        for item in history["history"][:5]:
            st.sidebar.write(f"📅 {item['name']} - {item.get('host', 'Unknown')}")
    else:
        st.sidebar.write("No recent connections")
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📜 My Hosts", "➕ Add Host", "📂 Import SSH Config", "⚙️ Settings"])
    
    # Tab 1: My Hosts
    with tab1:
        st.header("Your SSH Hosts")
        
        if not hosts:
            st.info("No hosts added yet. Click on 'Add Host' to add your first SSH connection!")
        else:
            for idx, host in enumerate(hosts):
                name = host.get('name', f'Host {idx+1}')
                display_host = decrypt_data(host.get('host', '')) or host.get('host', 'Unknown')
                display_user = decrypt_data(host.get('username', '')) or host.get('username', 'Unknown')
                
                col1, col2, col3, col4 = st.columns([2, 1, 1, 0.5])
                
                with col1:
                    st.markdown(f"### {name}")
                    st.write(f"🌐 {display_host}")
                    st.write(f"👤 {display_user}")
                    st.write(f"🔢 Port: {host.get('port', 22)}")
                    if host.get('key_file'):
                        st.write(f"🔑 {Path(decrypt_data(host['key_file'])).name}")
                    if host.get('forward_local') or host.get('forward_remote') or host.get('forward_dynamic'):
                        st.markdown("**Port Forwarding:**")
                        if host.get('forward_local'):
                            st.write(f"  Local: {host['forward_local']}")
                        if host.get('forward_remote'):
                            st.write(f"  Remote: {host['forward_remote']}")
                        if host.get('forward_dynamic'):
                            st.write(f"  Dynamic: {host['forward_dynamic']}")
                
                with col2:
                    if st.button("🔄 Test", key=f"test_{idx}"):
                        is_online = test_ssh_connection(host)
                        if is_online:
                            st.success("✅ Host is online!")
                        else:
                            st.error("❌ Host is offline or connection failed")
                
                with col3:
                    if st.button("👁️ Preview", key=f"preview_{idx}"):
                        cmd = ssh_connection(host, dry_run=True)
                        st.code(cmd, language="bash")
                    if st.button("🔌 Connect", key=f"connect_{idx}"):
                        ssh_connection(host)
                
                with col4:
                    if st.button("🗑️", key=f"delete_{idx}"):
                        delete_host(idx)
    
    # Tab 2: Add Host
    with tab2:
        st.header("Add New SSH Host")
        
        name = st.text_input("Host Name (label)")
        host = st.text_input("Hostname / IP Address")
        username = st.text_input("Username", "root")
        port = st.number_input("Port", value=22, min_value=1, max_value=65535)
        
        key_file = st.text_input("SSH Key File Path (optional)")
        
        st.subheader("Port Forwarding (Optional)")
        col1, col2, col3 = st.columns(3)
        with col1:
            forward_local = st.text_input("Local Forward", help="Format: [BIND_ADDRESS:]PORT:HOST:PORT")
        with col2:
            forward_remote = st.text_input("Remote Forward", help="Format: [BIND_ADDRESS:]PORT:HOST:PORT")
        with col3:
            forward_dynamic = st.text_input("Dynamic (SOCKS)", help="Port number for SOCKS proxy")
        
        if st.button("💾 Save Host"):
            if name and host:
                new_host = {
                    "name": name,
                    "host": host,
                    "username": username,
                    "port": port,
                    "key_file": key_file if key_file else None,
                    "forward_local": forward_local if forward_local else None,
                    "forward_remote": forward_remote if forward_remote else None,
                    "forward_dynamic": forward_dynamic if forward_dynamic else None,
                    "created_at": datetime.now().isoformat()
                }
                
                hosts = load_hosts()
                hosts.append(new_host)
                save_hosts(hosts)
                
                st.success(f"✅ Host '{name}' saved securely!")
                st.rerun()
            else:
                st.error("Please fill in at least Name and Hostname")
    
    # Tab 3: Import SSH Config
    with tab3:
        st.header("Import SSH Config")
        
        ssh_config_path = Path.home() / ".ssh" / "config"
        if ssh_config_path.exists():
            st.success(f"Found SSH config at `{ssh_config_path}`")
            
            if st.button("📥 Import All Hosts"):
                imported = import_ssh_config()
                if imported:
                    hosts = load_hosts()
                    hosts.extend(imported)
                    save_hosts(hosts)
                    st.success(f"✅ Imported {len(imported)} hosts!")
                    st.rerun()
                else:
                    st.error("Failed to import hosts")
            
            if st.button("👁️ Preview Import"):
                imported = import_ssh_config()
                if imported:
                    st.write(f"Found **{len(imported)}** hosts:")
                    for h in imported:
                        st.write(f"- {h.get('name', 'Unknown')}: {h.get('host', 'Unknown')}")
                else:
                    st.error("No hosts found in SSH config")
        else:
            st.info("No SSH config file found at ~/.ssh/config")
        
        st.subheader("Export Hosts")
        if st.button("📤 Export to JSON"):
            hosts = load_hosts()
            export_data = []
            for host in hosts:
                export_host = host.copy()
                if host.get('username'):
                    export_host['username'] = decrypt_data(host['username'])
                if host.get('host'):
                    export_host['host'] = decrypt_data(host['host'])
                if host.get('key_file'):
                    export_host['key_file'] = decrypt_data(host['key_file'])
                export_data.append(export_host)
            
            json_str = json.dumps(export_data, indent=2)
            st.download_button("Download JSON", json_str, file_name="ssh_hosts_export.json")
    
    # Tab 4: Settings
    with tab4:
        st.header("Settings")
        
        st.subheader("Management")
        if st.button("🗑️ Clear All Hosts"):
            if st.checkbox("Confirm clear all hosts"):
                save_hosts([])
                st.success("All hosts cleared!")
                st.rerun()
        
        if st.button("🗑️ Clear History"):
            if st.checkbox("Confirm clear history"):
                save_history({"history": []})
                st.success("Connection history cleared!")
                st.rerun()
        
        st.subheader("Security")
        if st.button("🔧 Regenerate Encryption Key"):
            if st.checkbox("Confirm key regeneration (will require re-adding hosts)"):
                if KEY_FILE.exists():
                    KEY_FILE.unlink()
                save_hosts([])
                st.success("Encryption key regenerated! Please re-add your hosts.")
                st.rerun()
        
        st.subheader("About")
        st.info("🛡️ **Security Features:**")
        st.write("- 🔐 Sensitive data encrypted with Fernet")
        st.write("- 🗂️ Keys stored in `~/.ssh_manager/`")
        st.write("- 📝 No API keys exposed")
        st.write("- 🛡️ Local-only storage")
        
        st.warning("⚠️ **Important:** Keep your encryption key safe! If lost, you'll need to re-add all hosts.")
        
        st.subheader("Recent Connections")
        if history.get("history"):
            for item in history["history"]:
                st.code(item['command'], language="bash")
                st.caption(f"📅 {item['timestamp']}")
        else:
            st.info("No recent connections")

if __name__ == "__main__":
    main()
