#!/usr/bin/env python3
"""
Network Monitoring: Ping + Traceroute
Stores results in ClickHouse
"""
import subprocess
import time
import asyncio
import yaml
from datetime import datetime, timezone
from ping3 import ping
from scapy.all import IP, ICMP, sr1
from clickhouse_driver import Client

# ---- CONFIG ----
CONFIG_FILE = "destinations.yaml"
CLICKHOUSE_HOST = "localhost"
CH_USER = "admin"
CH_PASSWORD = "secret123"
CH_DATABASE = "default"

# ---- LOAD DESTINATIONS ----
def load_destinations(config_file):
    with open(config_file, "r") as f:
        cfg = yaml.safe_load(f)
    return cfg.get("destinations", [])

# ---- CLICKHOUSE CLIENT ----
client = Client(
    host=CLICKHOUSE_HOST,
    user=CH_USER,
    password=CH_PASSWORD,
    database=CH_DATABASE
)
#client = Client(
#   host='192.168.100.132',   # change to match your environment
#   port=9000,
#   user='admin',
#   password='secret123',
#   database='default'
#)
def create_tables():
    client.execute("""
    CREATE TABLE IF NOT EXISTS device_ping_metrics (
        device String,
        ip String,
        packet_loss Float32,
        latency_min Float32,
        latency_avg Float32,
        latency_max Float32,
        status UInt8,
        poll_timestamp DateTime
    ) ENGINE = MergeTree()
    PARTITION BY toDate(poll_timestamp)
    ORDER BY (ip, poll_timestamp);
    """)
    
    client.execute("""
    CREATE TABLE IF NOT EXISTS traceroute_hops (
        device String,
        destination_ip String,
        hop_num UInt8,
        hop_ip String,
        roundtrip_time_ms Float32,
        poll_timestamp DateTime
    ) ENGINE = MergeTree()
    PARTITION BY toDate(poll_timestamp)
    ORDER BY (device, destination_ip, hop_num);
    """)


# ---- PING ----
def ping_host(ip, count=4, timeout=2):
    from ping3 import ping
    latencies = []
    lost = 0
    for _ in range(count):
        try:
            result = ping(ip, timeout=timeout, unit="ms", method="udp")
        except Exception:
            result = None

        if result is None:
            lost += 1
        else:
            latencies.append(result)
        time.sleep(0.2)

    packet_loss = lost / count * 100
    latency_min = min(latencies) if latencies else -0.0
    latency_max = max(latencies) if latencies else -0.0
    latency_avg = sum(latencies) / len(latencies) if latencies else -0.0
    status = 1 if packet_loss < 100 else 0
    return packet_loss, latency_min, latency_avg, latency_max, status

def store_ping_metrics(device, ip, packet_loss, latency_min, latency_avg, latency_max, status):
    client.execute("""
      INSERT INTO device_ping_metrics
      (device, ip, packet_loss, latency_min, latency_avg, latency_max, status, poll_timestamp)
      VALUES
      """, [(device, ip, packet_loss, latency_min, latency_avg, latency_max, status, datetime.now(timezone.utc))])

# ---- TRACEROUTE ----
def traceroute_host(ip, max_hops=30):
    hops = []
    cmd = ["traceroute", "-n", "-m", str(max_hops), ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            hop_number = int(parts[0])
            hop_ip = parts[1]
            # RTTs: convert to float, fallback to -1.0 if not numeric
            rtt_values = []
            for p in parts[2:]:
                try:
                    rtt_values.append(float(p.replace("ms", "")))
                except ValueError:
                    rtt_values.append(-1.0)
            avg_rtt = sum(rtt_values)/len(rtt_values) if rtt_values else -1.0
            hops.append({
                "hop_number": hop_number,
                "hop_ip": hop_ip,
                "roundtrip_time_ms": avg_rtt
            })
        return hops
    except Exception as e:
        print(f"Traceroute failed: {e}")
        return []

def store_traceroute(device, ip, hops):
    rows = []
    ts = datetime.now(timezone.utc)
    for hop in hops:
        rtt = hop.get("roundtrip_time_ms")
        rows.append((
            device,
            ip,
            hop.get("hop_number"),
            hop.get("hop_ip"),
            float(rtt) if rtt is not None else -1.0,
            ts
        ))

    # Use the global client (no need to recreate it)
    client.execute("""
        INSERT INTO traceroute_hops
        (device, destination_ip, hop_num, hop_ip, roundtrip_time_ms, poll_timestamp)
        VALUES
    """, rows)

# ---- MAIN ----
def main():
    create_tables()
    destinations = load_destinations(CONFIG_FILE)

    for dest in destinations:
        device = dest.get("name", dest["ip"])
        ip = dest["ip"]

        print(f"🔹 Pinging {device} ({ip})...")
        packet_loss, latency_min, latency_avg, latency_max, status = ping_host(ip)
        print(f"  Status={status}, Loss={packet_loss}%, Avg Latency={latency_avg}ms")
        store_ping_metrics(device, ip, packet_loss, latency_min, latency_avg, latency_max, status)

        print(f"🔹 Tracerouting {device} ({ip})...")
        hops = traceroute_host(ip)
        print(f"  Hops: {hops}")
        store_traceroute(device, ip, hops)


if __name__ == "__main__":
    main()
