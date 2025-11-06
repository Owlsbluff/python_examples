#!/usr/bin/env python3
import asyncio
import psycopg2
from psycopg2.extras import RealDictCursor
import ipaddress
import os
from datetime import datetime, timedelta
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# Database config
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'network_monitoring',
    'user': 'myuser'
}

# Encryption key (must be exactly 32 characters/bytes)
ENCRYPTION_KEY = os.environ.get('SNMP_ENCRYPTION_KEY', '').encode('utf-8')

if len(ENCRYPTION_KEY) != 32:
    print(f"ERROR: SNMP_ENCRYPTION_KEY must be exactly 32 characters! Currently: {len(ENCRYPTION_KEY)}")
    exit(1)

def encrypt_string(plaintext):
    """Encrypt a string for storage - matches Node.js implementation"""
    if not plaintext:
        return None
    
    iv = b'\x00' * 16  # 16 bytes of zeros to match Node.js
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to be a multiple of 16 bytes (AES block size)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')
def decrypt_string(ciphertext):
    """Decrypt a string from storage - matches Node.js implementation"""
    if not ciphertext:
        return None
    
    try:
        # Handle bytes from database
        if isinstance(ciphertext, memoryview):
            ciphertext = bytes(ciphertext).decode('utf-8')
        elif isinstance(ciphertext, bytes):
            ciphertext = ciphertext.decode('utf-8')
        
        # Remove any whitespace
        ciphertext = ciphertext.strip()
        
        # Decrypt
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        encrypted_bytes = base64.b64decode(ciphertext)
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        result = decrypted.decode('utf-8')
        print(f"   Decrypted successfully: {result[:3]}***")
        return result
        
    except Exception as e:
        print(f"   Decryption error: {e}")
        # Try to return as plain text
        return str(ciphertext)

async def snmp_get(host, community, oid, version='2c'):
    """Simple SNMP GET using snmpget command"""
    print(f"    🔍 Attempting SNMP: snmpget -v2c -c {community} -Oqv {host} {oid}")
    try:
        if version == '2c':
            # Add explicit error handling
            try:
                proc = await asyncio.create_subprocess_exec(
                    'snmpget', '-v2c', '-c', community, '-Oqv', host, oid,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                print(f"    ✅ Process created for {host}")
            except FileNotFoundError:
                print(f"    ❌ snmpget command not found!")
                return None
            except Exception as e:
                print(f"    ❌ Failed to create process: {e}")
                return None
        else:
            return None
        
        print(f"    ⏳ Waiting for response from {host}...")
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=2)
        
        print(f"    📥 Return code: {proc.returncode}, stdout length: {len(stdout) if stdout else 0}")
        
        if proc.returncode == 0 and stdout:
            val = stdout.decode().strip().strip('"')
            if 'No Such' in val:
                print(f"    ⚠️ No Such Object")
                return None
            print(f"    ✅ Got value: {val[:50]}")
            return val
        else:
            if stderr:
                print(f"    ⚠️ STDERR: {stderr.decode().strip()[:100]}")
                
    except asyncio.TimeoutError:
        print(f"    ⏱️ Timeout waiting for {host}")
        return None
    except Exception as e:
        print(f"    ❌ Exception in snmp_get: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    return None
async def discover_device(ip, credentials, conn, ping_first=False):
    """Try to discover a single device"""
    ip_str = str(ip)

    # Try each credential until one works
    for cred in credentials:
        version = cred['version']

        if version in ('v2c', '2c'):  
            community = decrypt_string(cred['community_string'])
            if not community:
                continue

            # Pass '2c' to snmp_get (not 'v2c')
            sys_descr = await snmp_get(ip_str, community, '1.3.6.1.2.1.1.1.0', '2c')

            if sys_descr:
                sys_name = await snmp_get(ip_str, community, '1.3.6.1.2.1.1.5.0', '2c') or ip_str
                print(f"  ✅ {ip_str} - Found device: {sys_name}")
                return {
                    'ip': ip_str,
                    'sys_name': sys_name,
                    'sys_descr': sys_descr,
                    'credential_id': cred['id']
                }

    return None
async def discover_subnet(subnet_config, conn, cur):
    """Discover all devices in a subnet"""
    subnet_id = subnet_config['id']
    subnet = ipaddress.ip_network(subnet_config['subnet'])
    site_id = subnet_config['site_id']
    
    print(f"\n{'='*70}")
    print(f"🔍 Discovering subnet: {subnet} (Site ID: {site_id})")
    print(f"{'='*70}")
    
    # Get credentials for this subnet
    cur.execute("""
        SELECT * FROM snmp_credentials 
        WHERE id = %s
    """, (subnet_config['snmp_credential_id'],))
    credentials = cur.fetchall()
    
    if not credentials:
        print(f"⚠️ No credentials found for subnet {subnet}")
        return
    
    # Discover each IP with rate limiting
    hosts = list(subnet.hosts())
    found_count = 0
    
    # Process IPs one at a time (or in small batches)
    for i, ip in enumerate(hosts):
        if i % 10 == 0:
            print(f"📡 Scanning {i+1}/{len(hosts)}...")
        
        result = await discover_device(ip, credentials, conn)
        
        if result:
            found_count += 1
            ip = result['ip']
            sys_name = result['sys_name']
            sys_descr = result['sys_descr']
            
            # Check if device already exists
            cur.execute("""
                SELECT id FROM devices WHERE mgmt_ip = %s
            """, (ip,))
            existing = cur.fetchone()
            
            if existing:
                print(f"  ✓ {ip} ({sys_name}) - Already exists, skipping")
                log_discovery(cur, subnet_id, ip, sys_name, sys_descr, 'found_existing', 'Device already in database')
            else:
                # Add new device
                try:
                    device_type = extract_device_type(sys_descr)
                    
                    cur.execute("""
                        INSERT INTO devices (
                            site_id, device, device_type, role, mgmt_ip, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                        RETURNING id
                    """, (site_id, sys_name, device_type, 'discovered', ip))
                    
                    new_id = cur.fetchone()['id']
                    conn.commit()
                    
                    print(f"  ✅ {ip} ({sys_name}) - Added as new device (ID: {new_id})")
                    log_discovery(cur, subnet_id, ip, sys_name, sys_descr, 'found_new', f'Added as device ID {new_id}')
                except Exception as e:
                    conn.rollback()
                    print(f"  ❌ {ip} - Error adding device: {e}")
                    log_discovery(cur, subnet_id, ip, sys_name, sys_descr, 'error', str(e))
        
        # Small delay between requests to avoid overwhelming the network
        await asyncio.sleep(0.1)
    
    print(f"\n✅ Scan complete - Found {found_count} device(s)")
    
    # Update last discovery time
    cur.execute("""
        UPDATE discovery_subnets 
        SET last_discovery = NOW() 
        WHERE id = %s
    """, (subnet_id,))
    conn.commit()

def log_discovery(cur, subnet_id, ip, sys_name, sys_descr, status, message):
    """Log discovery attempt"""
    try:
        cur.execute("""
            INSERT INTO discovery_log (subnet_id, ip_address, sys_name, sys_descr, status, message)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (subnet_id, ip, sys_name, sys_descr, status, message))
    except Exception as e:
        print(f"  ⚠️ Error logging discovery: {e}")

def extract_device_type(sys_descr):
    """Try to extract device type from sysDescr"""
    if not sys_descr:
        return "Unknown"
    
    sys_descr_lower = sys_descr.lower()
    
    # Simple heuristics
    if 'cisco' in sys_descr_lower:
        if 'catalyst' in sys_descr_lower:
            return 'Cisco Catalyst Switch'
        elif 'asr' in sys_descr_lower:
            return 'Cisco ASR Router'
        elif 'nexus' in sys_descr_lower:
            return 'Cisco Nexus Switch'
        return 'Cisco Device'
    elif 'arista' in sys_descr_lower:
        return 'Arista Switch'
    elif 'juniper' in sys_descr_lower:
        return 'Juniper Device'
    elif 'linux' in sys_descr_lower:
        return 'Linux Server'
    
    return sys_descr[:50]  # First 50 chars

async def run_discovery():
    """Main discovery process"""
    print(f"\n{'='*70}")
    print(f"🚀 SNMP Autodiscovery Started - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")
    
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    
    # Mark discovery as running
    cur.execute("UPDATE discovery_config SET is_running = true, last_run = NOW()")
    conn.commit()
    
    try:
        # Get enabled subnets
        cur.execute("""
            SELECT ds.*, sc.version, sc.community_string
            FROM discovery_subnets ds
            LEFT JOIN snmp_credentials sc ON ds.snmp_credential_id = sc.id
            WHERE ds.enabled = true
            ORDER BY ds.id
        """)
        subnets = cur.fetchall()
        
        if not subnets:
            print("⚠️ No enabled discovery subnets found")
            return
        
        print(f"📋 Found {len(subnets)} subnet(s) to discover\n")
        
        # Discover each subnet
        for subnet in subnets:
            await discover_subnet(subnet, conn, cur)
        
        # Calculate next run time
        cur.execute("SELECT schedule_interval FROM discovery_config LIMIT 1")
        config = cur.fetchone()
        
        if config and config['schedule_interval'] != 'manual':
            hours = 12 if config['schedule_interval'] == '12h' else 24
            next_run = datetime.now() + timedelta(hours=hours)
            
            cur.execute("""
                UPDATE discovery_config 
                SET next_run = %s
            """, (next_run,))
            conn.commit()
            
            print(f"\n⏰ Next scheduled discovery: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
    
    finally:
        # Mark discovery as complete
        cur.execute("UPDATE discovery_config SET is_running = false")
        conn.commit()
        cur.close()
        conn.close()
    
    print(f"\n{'='*70}")
    print(f"✅ Discovery Complete - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

def should_run_discovery():
    """Check if it's time to run discovery"""
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    
    cur.execute("""
        SELECT schedule_interval, next_run, is_running 
        FROM discovery_config 
        LIMIT 1
    """)
    config = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not config:
        return False
    
    if config['is_running']:
        return False
    
    if config['schedule_interval'] == 'manual':
        return False
    
    if not config['next_run'] or datetime.now() >= config['next_run']:
        return True
    
    return False

def discovery_daemon():
    """Run discovery as a daemon that checks every hour"""
    print("🔄 SNMP Discovery Daemon Started")
    print("   Checking every hour for scheduled discoveries...")
    
    while True:
        if should_run_discovery():
            asyncio.run(run_discovery())
        
        # Sleep for 1 hour
        time.sleep(3600)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--daemon':
        # Run as daemon
        discovery_daemon()
    else:
        # Run once immediately
        asyncio.run(run_discovery())
