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
import pandas as pd
import streamlit as st
from datetime import datetime
from pathlib import Path
import subprocess
from cryptography.fernet import Fernet
import base64

# Configuration
CONFIG_DIR = Path.home() / ".ssh_manager"
CONFIG_FILE = CONFIG_DIR / "hosts.json"
KEY_FILE = CONFIG_DIR / "encryption.key"

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
        # Set restrictive permissions
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
        # Encrypt sensitive fields
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

def test_ssh_connection(host, username, key_file, timeout=5):
    """Test SSH connection to a host"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Decrypt values if encrypted
        if host.get('host'):
            host_addr = decrypt_data(host['host']) or host['host']
        else:
            host_addr = host['host']
            
        if host.get('username'):
            user = decrypt_data(host['username']) or host['username']
        else:
            user = host['username']
        
        if key_file and os.path.exists(key_file):
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host_addr, username=user, pkey=key, timeout=timeout)
        else:
            ssh.connect(host_addr, username=user, timeout=timeout)
        
        ssh.close()
        return True
    except Exception as e:
        return False

def ssh_connection(host, username, key_file=None, port=22):
    """Initiate SSH connection using system ssh command"""
    try:
        # Decrypt values if encrypted
        if host.get('host'):
            host_addr = decrypt_data(host['host']) or host['host']
        else:
            host_addr = host['host']
            
        if host.get('username'):
            user = decrypt_data(host['username']) or host['username']
        else:
            user = host['username']
        
        if key_file and os.path.exists(key_file):
            cmd = f"ssh -i {key_file} -p {port} {user}@{host_addr}"
        else:
            cmd = f"ssh -p {port} {user}@{host_addr}"
        
        print(f"Connecting to {host_addr} as {user}...")
        subprocess.run(cmd, shell=True)
        
    except Exception as e:
        st.error(f"Connection failed: {e}")

def delete_host(index):
    """Delete a host from the list"""
    hosts = load_hosts()
    del hosts[index]
    save_hosts(hosts)
    st.rerun()

def main():
    st.title("🔑 SSH Manager")
    st.markdown("## Manage your SSH connections securely")
    st.markdown('<span class="security-badge">🔒 Encrypted Storage</span>', unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.header("📊 Statistics")
    hosts = load_hosts()
    st.sidebar.metric("Total Hosts", len(hosts))
    
    # Tabs
    tab1, tab2, tab3 = st.tabs(["📜 My Hosts", "➕ Add Host", "⚙️ Settings"])
    
    # Tab 1: My Hosts
    with tab1:
        st.header("Your SSH Hosts")
        
        if not hosts:
            st.info("No hosts added yet. Click on 'Add Host' to add your first SSH connection!")
        else:
            for idx, host in enumerate(hosts):
                # Decrypt display values
                name = host.get('name', f'Host {idx+1}')
                display_host = decrypt_data(host.get('host', '')) or host.get('host', 'Unknown')
                display_user = decrypt_data(host.get('username', '')) or host.get('username', 'Unknown')
                
                col1, col2, col3, col4 = st.columns([2, 1, 1, 0.5])
                
                with col1:
                    st.markdown(f"### {name}")
                    st.write(f"🌐 {display_host}")
                    st.write(f"👤 {display_user}")
                    if host.get('key_file'):
                        st.write(f"🔑 {host['key_file']}")
                
                with col2:
                    if st.button("🔄 Test", key=f"test_{idx}"):
                        is_online = test_ssh_connection(host, host.get('username'), host.get('key_file'))
                        if is_online:
                            st.success("✅ Host is online!")
                        else:
                            st.error("❌ Host is offline or connection failed")
                
                with col3:
                    if st.button("🔌 Connect", key=f"connect_{idx}"):
                        ssh_connection(host, host.get('username'), host.get('key_file'), host.get('port', 22))
                
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
        
        if st.button("💾 Save Host"):
            if name and host:
                new_host = {
                    "name": name,
                    "host": host,
                    "username": username,
                    "port": port,
                    "key_file": key_file if key_file else None,
                    "created_at": datetime.now().isoformat()
                }
                
                hosts = load_hosts()
                hosts.append(new_host)
                save_hosts(hosts)
                
                st.success(f"✅ Host '{name}' saved securely!")
                st.rerun()
            else:
                st.error("Please fill in at least Name and Hostname")
    
    # Tab 3: Settings
    with tab3:
        st.header("Settings")
        
        if st.button("🗑️ Clear All Hosts"):
            if st.checkbox("Confirm clear all hosts"):
                save_hosts([])
                st.success("All hosts cleared!")
                st.rerun()
        
        if st.button("🔧 Regenerate Encryption Key"):
            if st.checkbox("Confirm key regeneration (will require re-adding hosts)"):
                if KEY_FILE.exists():
                    KEY_FILE.unlink()
                # Clear all hosts since they can't be decrypted
                save_hosts([])
                st.success("Encryption key regenerated! Please re-add your hosts.")
                st.rerun()
        
        st.subheader("Security Information")
        st.info("🛡️ **Security Features:**")
        st.write("- 🔐 Sensitive data encrypted with Fernet")
        st.write("- 🗂️ Keys stored in `~/.ssh_manager/`")
        st.write("- 📝 No API keys exposed")
        st.write("- 🛡️ Local-only storage")
        
        st.warning("⚠️ **Important:** Keep your encryption key safe! If lost, you'll need to re-add all hosts.")

if __name__ == "__main__":
    main()
