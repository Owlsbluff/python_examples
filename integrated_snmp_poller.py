#!/usr/bin/env python3
"""
Integrated SNMP Poller for Network Monitor
Reads devices from PostgreSQL and polls them periodically
"""
import asyncio
import clickhouse_connect
import yaml
import re
import psycopg2
from datetime import datetime, timezone
import os
import sys
import ipaddress
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import base64


# ---- CONFIG FROM ENV ----
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "admin")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "secret123")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "default")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "network_monitoring")
POSTGRES_USER = os.getenv("POSTGRES_USER", "myuser")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")

OIDS_FILE = os.getenv("OIDS_FILE", "/home/user/streamnet/snmp/oids.yaml")
POLL_INTERVAL = int(os.getenv("SNMP_POLL_INTERVAL", "60"))

# ---- LOAD YAML FILES ----
def load_yaml(file_path):
    with open(file_path, "r") as f:
       return yaml.safe_load(f)

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

        # Get encryption key from env
        ENCRYPTION_KEY = os.environ.get('SNMP_ENCRYPTION_KEY', '').encode('utf-8')
        
        if len(ENCRYPTION_KEY) != 32:
            print(f"⚠️ SNMP_ENCRYPTION_KEY must be exactly 32 characters!")
            return None

        # Decrypt
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        encrypted_bytes = base64.b64decode(ciphertext)
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted.decode('utf-8')

    except Exception as e:
        print(f"⚠️ Decryption error: {e}")
        return None
# ---- LOAD DEVICES FROM POSTGRES ----
def load_devices_from_postgres():
    """Load devices from PostgreSQL database with SNMP credentials from discovery_subnets"""
    devices = []
    try:
        conn = psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            database=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD
        )
        cursor = conn.cursor()
        
        # Get all devices with management IPs
        cursor.execute("""
            SELECT device, mgmt_ip
            FROM devices
            WHERE mgmt_ip IS NOT NULL
        """)
        
        device_rows = cursor.fetchall()
        
        # Get all discovery subnets with credentials
        cursor.execute("""
            SELECT ds.subnet, sc.community_string, sc.version
            FROM discovery_subnets ds
            JOIN snmp_credentials sc ON ds.snmp_credential_id = sc.id
            WHERE ds.enabled = true
              AND sc.version = 'v2c'
        """)
        
        subnet_creds = cursor.fetchall()
        
        # Match devices to subnets and get credentials
        for device_name, mgmt_ip_str in device_rows:
            try:
                device_ip = ipaddress.ip_address(str(mgmt_ip_str))
                
                # Find matching subnet
                for subnet_str, community_encrypted, version in subnet_creds:
                    subnet = ipaddress.ip_network(subnet_str)
                    
                    if device_ip in subnet:
                        # Decrypt community string
                        try:
                            community = decrypt_string(community_encrypted)
                            if community:
                                devices.append({
                                    "name": device_name,
                                    "host": str(mgmt_ip_str),
                                    "community": community
                                })
                                print(f"  ✓ {device_name} ({mgmt_ip_str}) - matched to {subnet_str}")
                                break
                        except Exception as e:
                            print(f"⚠️ Error decrypting community for {device_name}: {e}")
                            continue
                            
            except Exception as e:
                print(f"⚠️ Error processing device {device_name}: {e}")
                continue
        
        cursor.close()
        conn.close()
        
        print(f"✅ Loaded {len(devices)} devices from PostgreSQL")
        return devices
        
    except Exception as e:
        print(f"❌ Error loading devices from PostgreSQL: {e}")
        import traceback
        traceback.print_exc()
        return []
# ---- SELECT OID PROFILE ----
def select_oids(sys_descr, oid_profiles):
    for profile in oid_profiles:
        if re.search(profile["match"], sys_descr, re.IGNORECASE):
            return profile.get("oids", {})
    generic_profile = next((p for p in oid_profiles if p.get("vendor") == "Generic"), {})
    return generic_profile.get("oids", {})

# ---- SNMP HELPERS ----
def clean_snmp_value(val):
    if not val:
        return "No Object"
    val = val.strip().strip('"')
    if "No Such" in val or "Timeout" in val:
        return "No Object"
    return val

async def snmp_get(host, community, oid):
    try:
        proc = await asyncio.create_subprocess_exec(
            'snmpget', '-v2c', '-c', community, '-Oqv', host, oid,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        if proc.returncode == 0 and stdout:
            return clean_snmp_value(stdout.decode())
        return "No Object"
    except asyncio.TimeoutError:
        print(f"⚠️ SNMP GET timeout for {host} OID {oid}")
        return "No Object"
    except Exception as e:
        print(f"⚠️ SNMP GET error for {host} OID {oid}: {e}")
        return "No Object"

async def snmp_walk(host, community, oid):
    results = {}
    try:
        proc = await asyncio.create_subprocess_exec(
            'snmpwalk', '-v2c', '-c', community, '-Oqv', host, oid,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode == 0 and stdout:
            lines = stdout.decode().strip().split('\n')
            for i, line in enumerate(lines, start=1):
                results[str(i)] = clean_snmp_value(line)

        if not results:
            proc = await asyncio.create_subprocess_exec(
                'snmpwalk', '-v2c', '-c', community, '-On', host, oid,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode == 0 and stdout:
                for line in stdout.decode().strip().split('\n'):
                    if '=' in line:
                        oid_part, val_part = line.split('=', 1)
                        idx = oid_part.strip().split('.')[-1]
                        val = clean_snmp_value(val_part.split(':', 1)[-1])
                        results[idx] = val
    except asyncio.TimeoutError:
        print(f"⚠️ SNMP WALK timeout for {host} OID {oid}")
    except Exception as e:
        print(f"⚠️ SNMP WALK error for {host} OID {oid}: {e}")
    return results

async def snmp_walk_lldp(host, community, oid):
    results = {}
    try:
        proc = await asyncio.create_subprocess_exec(
            'snmpwalk', '-v2c', '-c', community, '-On', host, oid,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode == 0 and stdout:
            for line in stdout.decode().strip().split('\n'):
                if '=' in line:
                    oid_part, val_part = line.split('=', 1)
                    oid_components = oid_part.strip().split('.')

                    if len(oid_components) >= 3:
                        local_port_idx = oid_components[-2]
                        val = clean_snmp_value(val_part.split(':', 1)[-1])

                        if local_port_idx not in results:
                            results[local_port_idx] = []
                        results[local_port_idx].append(val)

    except asyncio.TimeoutError:
        print(f"⚠️ SNMP WALK (LLDP) timeout for {host} OID {oid}")
    except Exception as e:
        print(f"⚠️ SNMP WALK (LLDP) error for {host} OID {oid}: {e}")
    return results

# ---- PING ----
async def ping(host):
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", host,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception as e:
        print(f"⚠️ Ping error for {host}: {e}")
        return False

# ---- POLLER ----
async def poll_device(dev, oid_profiles):
    host = dev.get("host")
    community = dev.get("community", "public")
    name = dev.get("name", host or "unknown")

    rows, lldp_rows = [], []

    try:
        if not host:
            print(f"⚠️ Invalid device entry (missing host): {dev}")
            return rows, lldp_rows

        reachable = await ping(host)
        device_status = 2 if reachable else 0
        if not reachable:
            print(f"⚠️ {name} ({host}) unreachable.")
            return rows, lldp_rows

        sys_descr = await snmp_get(host, community, "1.3.6.1.2.1.1.1.0")
        if sys_descr == "No Object":
            print(f"⚠️ {name} ({host}) - No sysDescr found.")
            return rows, lldp_rows

        print(f"✅ {name} ({host}) - {sys_descr[:80]}")
        oids = select_oids(sys_descr, oid_profiles)
        vendor = oids.get("vendor", "Generic")
        model = oids.get("model", "Unknown")

        # CPU / Memory
        cpu_raw = await snmp_get(host, community, oids.get("cpu", ""))
        try:
            cpu_val = float(cpu_raw)
        except Exception:
            cpu_val = 0.0

        mem_val, mem_free = 0.0, 0.0
        if oids.get("mem_used") and oids.get("mem_free"):
            mem_used_raw = await snmp_get(host, community, oids["mem_used"])
            mem_free_raw = await snmp_get(host, community, oids["mem_free"])
            try:
                mem_used = float(mem_used_raw)
                mem_free = float(mem_free_raw)
                total = mem_used + mem_free
                mem_val = (mem_used / total * 100) if total else 0
            except Exception:
                pass

        # Interfaces
        if_descrs = await snmp_walk(host, community, oids.get("ifDescr", "1.3.6.1.2.1.2.2.1.2"))
        if_index = await snmp_walk(host, community, oids.get("ifIndex", "1.3.6.1.2.1.2.2.1.1"))
        if_names = await snmp_walk(host, community, oids.get("ifName", "1.3.6.1.2.1.31.1.1.1.1"))
        if_aliases = await snmp_walk(host, community, oids.get("ifAlias", "1.3.6.1.2.1.31.1.1.1.18"))
        if_speeds = await snmp_walk(host, community, oids.get("ifSpeed", "1.3.6.1.2.1.2.2.1.5"))
        if_oper_status = await snmp_walk(host, community, "1.3.6.1.2.1.2.2.1.8")
        if_in_octets = await snmp_walk(host, community, oids.get("ifInOctets", "1.3.6.1.2.1.2.2.1.10"))
        if_out_octets = await snmp_walk(host, community, oids.get("ifOutOctets", "1.3.6.1.2.1.2.2.1.16"))
        if_in_ucast = await snmp_walk(host, community, oids.get("ifInUcastPkts", "1.3.6.1.2.1.2.2.1.11"))
        if_out_ucast = await snmp_walk(host, community, oids.get("ifOutUcastPkts", "1.3.6.1.2.1.2.2.1.17"))
        if_in_discards = await snmp_walk(host, community, oids.get("ifInDiscards", "1.3.6.1.2.1.2.2.1.13"))
        if_in_errors = await snmp_walk(host, community, oids.get("ifInErrors", "1.3.6.1.2.1.2.2.1.14"))
        if_out_discards = await snmp_walk(host, community, oids.get("ifOutDiscards", "1.3.6.1.2.1.2.2.1.19"))
        if_out_errors = await snmp_walk(host, community, oids.get("ifOutErrors", "1.3.6.1.2.1.2.2.1.20"))

        now = datetime.now(timezone.utc)
        if_index_to_name = {}
        
        for idx, if_descr in if_descrs.items():
            try:
                iface_state = 1 if if_oper_status.get(idx, "2") == "1" else 0
                iface_name = if_names.get(idx, if_descr)
                iface_idx = int(if_index.get(idx, 0))

                row = (
                    name, sys_descr, cpu_val, mem_val, mem_free,
                    iface_idx, iface_name,
                    int(if_in_octets.get(idx, 0)),
                    int(if_out_octets.get(idx, 0)),
                    int(if_in_ucast.get(idx, 0)),
                    int(if_out_ucast.get(idx, 0)),
                    int(if_in_discards.get(idx, 0)),
                    int(if_in_errors.get(idx, 0)),
                    int(if_out_discards.get(idx, 0)),
                    int(if_out_errors.get(idx, 0)),
                    now, device_status, iface_state,
                    iface_name, if_aliases.get(idx, ""),
                    if_descr, int(if_speeds.get(idx, 0)),
                    vendor, model
                )
                rows.append(row)
                if_index_to_name[str(iface_idx)] = iface_name

            except Exception as inner_e:
                print(f"⚠️ {name} interface parse error idx={idx}: {inner_e}")

        # LLDP
        lldpRemSysName = await snmp_walk_lldp(host, community, oids.get("lldpRemSysName", "1.0.8802.1.1.2.1.4.1.1.9"))
        lldpRemPortId = await snmp_walk_lldp(host, community, oids.get("lldpRemPortId", "1.0.8802.1.1.2.1.4.1.1.7"))
        lldpRemPortDesc = await snmp_walk_lldp(host, community, oids.get("lldpRemPortDesc", "1.0.8802.1.1.2.1.4.1.1.8"))

        if isinstance(lldpRemSysName, dict) and lldpRemSysName:
            for local_port_idx, remote_devices in lldpRemSysName.items():
                local_port_name = if_index_to_name.get(local_port_idx, f"if{local_port_idx}")

                for i, remote_dev in enumerate(remote_devices):
                    remote_port = "unknown"
                    remote_desc = ""

                    if local_port_idx in lldpRemPortId and i < len(lldpRemPortId[local_port_idx]):
                        remote_port = lldpRemPortId[local_port_idx][i]
                    if local_port_idx in lldpRemPortDesc and i < len(lldpRemPortDesc[local_port_idx]):
                        remote_desc = lldpRemPortDesc[local_port_idx][i]

                    lldp_rows.append((
                        name, local_port_name,
                        remote_dev or "unknown",
                        remote_port, remote_desc, now
                    ))

    except Exception as e:
        print(f"⚠️ poll_device() error for {name}: {e}")

    return rows, lldp_rows

# ---- CLICKHOUSE WRITE ----
def write_clickhouse(interface_rows, lldp_rows):
    client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE
    )

    if not isinstance(interface_rows, list):
        print(f"⚠️ interface_rows is {type(interface_rows)}, skipping")
        return
    if not isinstance(lldp_rows, list):
        lldp_rows = []

    # Ensure tables exist
    client.command("""
        CREATE TABLE IF NOT EXISTS snmp_metrics (
            device String, sys_descr String,
            cpu_usage Float32, mem_usage Float32, mem_free UInt64,
            if_index UInt32, interface String,
            if_in_octets UInt64, if_out_octets UInt64,
            if_in_ucast_pkts UInt64, if_out_ucast_pkts UInt64,
            if_in_discards UInt64, if_in_errors UInt64,
            if_out_discards UInt64, if_out_errors UInt64,
            poll_timestamp DateTime, device_status UInt8,
            interface_status UInt8, if_name String, if_alias String,
            if_descr String, if_speed UInt64, vendor String, model String
        ) ENGINE = MergeTree() ORDER BY (device, poll_timestamp)
    """)

    client.command("""
        CREATE TABLE IF NOT EXISTS lldp_neighbors (
            local_device String, local_port String,
            remote_device String, remote_port String,
            remote_descr String, poll_timestamp DateTime
        ) ENGINE = MergeTree() ORDER BY (local_device, poll_timestamp)
    """)

    if interface_rows:
        client.insert('snmp_metrics', interface_rows, column_names=[
            'device', 'sys_descr', 'cpu_usage', 'mem_usage', 'mem_free',
            'if_index', 'interface', 'if_in_octets', 'if_out_octets',
            'if_in_ucast_pkts', 'if_out_ucast_pkts',
            'if_in_discards', 'if_in_errors', 'if_out_discards', 'if_out_errors',
            'poll_timestamp', 'device_status', 'interface_status',
            'if_name', 'if_alias', 'if_descr', 'if_speed', 'vendor', 'model'
        ])

    cleaned_lldp_rows = [
        (ld, lp or "unknown", rd or "unknown", rp or "unknown", rdesc or "", ts)
        for ld, lp, rd, rp, rdesc, ts in lldp_rows
    ]

    if cleaned_lldp_rows:
        client.insert('lldp_neighbors', cleaned_lldp_rows, column_names=[
            'local_device', 'local_port', 'remote_device', 'remote_port', 'remote_descr', 'poll_timestamp'
        ])

# ---- MAIN LOOP ----
async def run_forever():
    oid_profiles = load_yaml(OIDS_FILE).get("devices", [])

    while True:
        print(f"\n{'='*70}")
        print(f"🔄 Starting SNMP poll at {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}")
        print(f"{'='*70}")
        
        try:
            devices = load_devices_from_postgres()
            
            if not devices:
                print("⚠️ No devices found in database")
                await asyncio.sleep(POLL_INTERVAL)
                continue
            
            results = await asyncio.gather(*[poll_device(dev, oid_profiles) for dev in devices])
            all_rows = [r for rows, _ in results for r in rows]
            all_lldp = [r for _, lldp in results for r in lldp]
            write_clickhouse(all_rows, all_lldp)
            print(f"✅ Inserted {len(all_rows)} interfaces, {len(all_lldp)} LLDP neighbors.")
        except Exception as e:
            print(f"❌ Polling error: {e}")
            import traceback
            traceback.print_exc()

        print(f"\n⏳ Sleeping for {POLL_INTERVAL}s...\n")
        await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    print("🚀 Starting Integrated SNMP Poller")
    print(f"📊 ClickHouse: {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}")
    print(f"🗄️  PostgreSQL: {POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
    print(f"⏱️  Poll Interval: {POLL_INTERVAL}s")
    print(f"📝 OIDs File: {OIDS_FILE}\n")
    
    asyncio.run(run_forever())
