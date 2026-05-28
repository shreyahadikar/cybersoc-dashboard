from scapy.all import sniff
from collections import defaultdict
import requests
import time
import json

# ==========================================
# FLOW STORAGE
# ==========================================

flows = defaultdict(lambda: {

    "packets": 0,

    "bytes": 0,

    "start_time": time.time()

})

API_URL = "http://127.0.0.1:5000/network_predict"

LOG_FILE = "network_logs.json"


# ==========================================
# SAVE LOGS
# ==========================================

def save_log(data):

    try:

        with open(LOG_FILE, "a") as f:

            json.dump(data, f)

            f.write("\n")

    except Exception as e:

        print("LOG ERROR:", e)


# ==========================================
# PROCESS PACKETS
# ==========================================

def process_packet(packet):

    try:

        # ==========================================
        # IP PACKETS ONLY
        # ==========================================

        if packet.haslayer("IP"):

            src_ip = packet["IP"].src

            dst_ip = packet["IP"].dst

            flow_id = f"{src_ip}-{dst_ip}"

            # ==========================================
            # UPDATE FLOW STATS
            # ==========================================

            flows[flow_id]["packets"] += 1

            flows[flow_id]["bytes"] += len(packet)

            duration = (
                time.time()
                -
                flows[flow_id]["start_time"]
            )

            # ==========================================
            # PORT DETECTION
            # ==========================================

            dst_port = 0

            if packet.haslayer("TCP"):

                dst_port = packet["TCP"].dport

            elif packet.haslayer("UDP"):

                dst_port = packet["UDP"].dport

            # ==========================================
            # CREATE NETWORK FEATURES
            # ==========================================

            payload = {

                "packets":
                flows[flow_id]["packets"],

                "bytes":
                flows[flow_id]["bytes"],

                "duration":
                duration,

                "dst_port":
                dst_port
            }

            # ==========================================
            # SEND TO ML IDS
            # ==========================================

            response = requests.post(

                API_URL,

                json=payload

            )

            result = response.json()

            # ==========================================
            # CREATE LOG ENTRY
            # ==========================================

            log_entry = {

                "timestamp":
                time.strftime("%Y-%m-%d %H:%M:%S"),

                "src_ip":
                src_ip,

                "dst_ip":
                dst_ip,

                "dst_port":
                dst_port,

                "packets":
                flows[flow_id]["packets"],

                "bytes":
                flows[flow_id]["bytes"],

                "duration":
                round(duration, 2),

                "detection":
                result
            }

            # ==========================================
            # PRINT ALERT
            # ==========================================

            print("\n================================")

            print("NETWORK TRAFFIC DETECTED")

            print(log_entry)

            print("================================")

            # ==========================================
            # SAVE LOG
            # ==========================================

            save_log(log_entry)

    except Exception as e:

        print("PACKET ERROR:", e)


# ==========================================
# START SNIFFER
# ==========================================

print("\nREAL-TIME IDS STARTED...")

sniff(

    prn=process_packet,

    store=False

)