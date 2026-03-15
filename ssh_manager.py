#!/usr/bin/env python3
"""
SSH Manager - A simple SSH connection manager application
Manage your SSH hosts, usernames, and keys with a beautiful UI
"""

import os
import json
import paramiko
import pandas as pd
import streamlit as st
from datetime import datetime
from pathlib import Path
import threading
import subprocess
import time

# Configuration
CONFIG_DIR = Path.home() / ".ssh_manager"
CONFIG_FILE = CONFIG_DIR / "hosts.json"

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
</style>
""", unsafe_allow_html=True)

def load_hosts():
    """Load SSH hosts from config file"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return []

def save_hosts(hosts):
    """Save SSH hosts to config file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(hosts, f, indent=2)

def test_ssh_connection(host, username, key_file, timeout=5):
    """Test SSH connection to a host"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if key_file and os.path.exists(key_file):
            key = paramiko.RSAKey.from_private_key_file(key_file)
            ssh.connect(host, username=username, pkey=key, timeout=timeout)
        else:
            ssh.connect(host, username=username, timeout=timeout)
        
        ssh.close()
        return True
    except Exception as e:
        return False

def ssh_connection(host, username, key_file=None, port=22):
    """Initiate SSH connection using system ssh command"""
    try:
        if key_file and os.path.exists(key_file):
            cmd = f"ssh -i {key_file} -p {port} {username}@{host}"
        else:
            cmd = f"ssh -p {port} {username}@{host}"
        
        print(f"Connecting to {host} as {username}...")
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
    st.markdown("## Manage your SSH connections with ease")
    
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
            # Convert to DataFrame for better display
            df = pd.DataFrame(hosts)
            
            for idx, host in enumerate(hosts):
                col1, col2, col3, col4 = st.columns([2, 1, 1, 0.5])
                
                with col1:
                    st.markdown(f"### {host['name']}")
                    st.write(f"🌐 {host['host']}")
                    st.write(f"👤 {host['username']}")
                    if host.get('key_file'):
                        st.write(f"🔑 {Path(host['key_file']).name}")
                
                with col2:
                    if st.button("🔄 Test", key=f"test_{idx}"):
                        is_online = test_ssh_connection(host['host'], host['username'], host.get('key_file'))
                        if is_online:
                            st.success("✅ Host is online!")
                        else:
                            st.error("❌ Host is offline or connection failed")
                
                with col3:
                    if st.button("🔌 Connect", key=f"connect_{idx}"):
                        ssh_connection(host['host'], host['username'], host.get('key_file'), host.get('port', 22))
                
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
                
                st.success(f"✅ Host '{name}' saved successfully!")
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
        
        if st.button("🔧 Reset Configuration"):
            if (CONFIG_FILE / "hosts.json").exists():
                (CONFIG_FILE / "hosts.json").unlink()
            st.success("Configuration reset!")
            st.rerun()
        
        st.subheader("About")
        st.info("SSH Manager v1.0 - Manage your SSH connections with ease")
        st.write("Created with Streamlit and Paramiko")

if __name__ == "__main__":
    main()
