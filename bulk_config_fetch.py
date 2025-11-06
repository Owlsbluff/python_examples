#!/usr/bin/env python3
"""
Fetch running configs from all devices using credentials from PostgreSQL
"""
import time
import paramiko
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# Database config from environment
DB_CONFIG = {
    'host': os.environ.get('PG_HOST', 'localhost'),
    'port': int(os.environ.get('PG_PORT', '5432')),
    'database': os.environ.get('PG_DATABASE', 'network_monitoring'),
    'user': os.environ.get('PG_USER', 'netmon_user'),
    'password': os.environ.get('PG_PASSWORD', '')
}

# Encryption key
ENCRYPTION_KEY = os.environ.get('SNMP_ENCRYPTION_KEY', '').encode('utf-8')

if len(ENCRYPTION_KEY) != 32:
    print(f"ERROR: SNMP_ENCRYPTION_KEY must be exactly 32 characters! Currently: {len(ENCRYPTION_KEY)}")
    sys.exit(1)

def decrypt_string(ciphertext):
    """Decrypt a string from storage - handles PostgreSQL bytea"""
    if not ciphertext:
        return None

    try:
        # Handle different input types from database
        if isinstance(ciphertext, memoryview):
            # PostgreSQL bytea returned as memoryview - convert to bytes
            encrypted_bytes = bytes(ciphertext)
        elif isinstance(ciphertext, bytes):
            # Already bytes
            encrypted_bytes = ciphertext
        elif isinstance(ciphertext, str):
            # String - try base64 first, then hex
            ciphertext = ciphertext.strip()
            try:
                encrypted_bytes = base64.b64decode(ciphertext)
            except:
                try:
                    # Remove \x prefix if present
                    if ciphertext.startswith('\\x'):
                        ciphertext = ciphertext[2:]
                    encrypted_bytes = bytes.fromhex(ciphertext)
                except:
                    print(f"⚠️ Could not decode ciphertext: {ciphertext[:20]}...")
                    return None
        else:
            print(f"⚠️ Unknown ciphertext type: {type(ciphertext)}")
            return None

        # Debug: print length
        print(f"  🔍 Encrypted data length: {len(encrypted_bytes)} bytes")
        
        # Check if data length is valid (must be multiple of 16 for AES)
        if len(encrypted_bytes) % 16 != 0:
            print(f"  ⚠️ Invalid encrypted data length: {len(encrypted_bytes)} (not multiple of 16)")
            # Try to pad to next multiple of 16
            padding_needed = 16 - (len(encrypted_bytes) % 16)
            print(f"  ⚠️ Data appears corrupted or not properly encrypted")
            return None

        # Decrypt
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        result = decrypted.decode('utf-8')
        print(f"  ✅ Decrypted successfully: {result[:3]}***")
        return result

    except Exception as e:
        print(f"⚠️ Decryption error: {e}")
        import traceback
        traceback.print_exc()
        return None


def get_device_config(device):
    """SSH to a device and fetch running config"""
    print(f"  🔍 Connecting to {device['device']} ({device['mgmt_ip']})...")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=str(device['mgmt_ip']),
            username=device['username'],
            password=device['password'],
            look_for_keys=False,
            allow_agent=False,
            timeout=15
        )

        chan = ssh.invoke_shell()
        time.sleep(0.5)

        # Flush initial banner
        while chan.recv_ready():
            chan.recv(9999)

        # Send newline to get prompt
        chan.send("\n")
        time.sleep(0.5)
        prompt_output = ""
        while chan.recv_ready():
            prompt_output += chan.recv(9999).decode("utf-8", errors="ignore")
        
        prompt = ""
        if prompt_output.strip().splitlines():
            prompt = prompt_output.strip().splitlines()[-1]

        # Enter enable mode if prompt ends with ">"
        if prompt.endswith(">"):
            chan.send("enable\n")
            time.sleep(0.5)

            # Read enable response
            enable_output = ""
            while chan.recv_ready():
                enable_output += chan.recv(9999).decode("utf-8", errors="ignore")

            # Check if a password is requested
            if "Password" in enable_output or "password" in enable_output.lower():
                if device.get("enable_password"):
                    chan.send(device["enable_password"] + "\n")
                    time.sleep(0.5)
                    # Clear any remaining output
                    while chan.recv_ready():
                        chan.recv(9999)
                else:
                    print(f"  ⚠️ Enable password requested but not available")

        # Disable paging
        chan.send("terminal length 0\n")
        time.sleep(0.5)
        while chan.recv_ready():
            chan.recv(9999)

        # Send the command
        chan.send(f"{device['command']}\n")
        time.sleep(1)

        # Read output until we see the # prompt
        config_output = ""
        timeout = 20
        start_time = time.time()
        while True:
            if chan.recv_ready():
                out = chan.recv(9999).decode("utf-8", errors="ignore")
                config_output += out
                lines = config_output.strip().splitlines()
                if lines and lines[-1].strip().endswith("#"):
                    break
            if time.time() - start_time > timeout:
                print(f"  ⚠️ Timeout waiting for output")
                break
            time.sleep(0.2)

        ssh.close()
        
        if config_output.strip():
            print(f"  ✅ Config fetched ({len(config_output)} bytes)")
            return config_output.strip()
        else:
            print(f"  ❌ No config received")
            return None

    except Exception as e:
        print(f"  ❌ Error: {e}")
        return None


def store_config_in_db(conn, device_id, config):
    """Insert or update config in PostgreSQL"""
    cur = conn.cursor()

    query = """
        INSERT INTO device_configurations (device_id, config, config_type, backup_type, changed_by)
        VALUES (%s, %s, 'latest_fetched', 'manual', 'Bulk Refresh')
        ON CONFLICT (device_id, config_type)
        DO UPDATE SET
            config = EXCLUDED.config,
            backup_type = 'manual',
            changed_by = 'Bulk Refresh',
            created_at = now();
    """
    cur.execute(query, (device_id, config))
    conn.commit()
    cur.close()


def main():
    print(f"\n{'='*70}")
    print(f"🚀 Bulk Config Fetch Started - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    # Connect to database
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    cur = conn.cursor()

    # Get all devices with SSH credentials
    cur.execute("""
        SELECT 
            d.id,
            d.device,
            d.mgmt_ip,
            d.device_type,
            d.ssh_username,
            d.ssh_password,
            d.enable_password
        FROM devices d
        WHERE d.mgmt_ip IS NOT NULL
          AND d.ssh_username IS NOT NULL
          AND d.ssh_password IS NOT NULL
        ORDER BY d.device
    """)

    devices = cur.fetchall()

    if not devices:
        print("⚠️ No devices with SSH credentials found")
        cur.close()
        conn.close()
        return

    print(f"📋 Found {len(devices)} devices to fetch configs from\n")

    success_count = 0
    fail_count = 0

    for device in devices:
        # Try to decrypt passwords, fallback to plain text
        ssh_password = None
        
        if device['ssh_password']:
            # Check if it's plain text (short length, not multiple of 16)
            pwd_bytes = bytes(device['ssh_password']) if isinstance(device['ssh_password'], memoryview) else device['ssh_password']
            
            if len(pwd_bytes) % 16 != 0:
                # Likely plain text
                ssh_password = pwd_bytes.decode('utf-8')
                print(f"  ℹ️ Using plain text password for {device['device']}")
            else:
                # Try to decrypt
                ssh_password = decrypt_string(device['ssh_password'])
        
        if not ssh_password:
            print(f"⚠️ {device['device']} - No valid SSH password, skipping")
            fail_count += 1
            continue
        
        # Same for enable password
        enable_password = None
        if device['enable_password']:
            en_pwd_bytes = bytes(device['enable_password']) if isinstance(device['enable_password'], memoryview) else device['enable_password']
            
            if len(en_pwd_bytes) % 16 != 0:
                enable_password = en_pwd_bytes.decode('utf-8')
            else:
                enable_password = decrypt_string(device['enable_password'])

        # Determine command based on device type
        command = 'show running-config'
        if device['device_type']:
            device_type_lower = device['device_type'].lower()
            if 'arista' in device_type_lower:
                command = 'show running-config'
            elif 'cisco' in device_type_lower:
                command = 'show running-config'
            elif 'juniper' in device_type_lower:
                command = 'show configuration'

        device_info = {
            'device': device['device'],
            'mgmt_ip': device['mgmt_ip'],
            'username': device['ssh_username'],
            'password': ssh_password,
            'enable_password': enable_password,
            'command': command
        }

        config = get_device_config(device_info)

        if config:
            store_config_in_db(conn, device['id'], config)
            success_count += 1
        else:
            fail_count += 1

        # Small delay between devices
        time.sleep(0.5)

    cur.close()
    conn.close()

    print(f"\n{'='*70}")
    print(f"✅ Bulk Config Fetch Complete")
    print(f"   Success: {success_count}")
    print(f"   Failed:  {fail_count}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
