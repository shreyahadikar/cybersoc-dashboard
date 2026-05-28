import requests

url = "http://127.0.0.1:5000/network_predict"

# =========================================
# CHANGE VALUES TO TEST DIFFERENT ATTACKS
# =========================================

data = {

    "packets": 10,

    "bytes": 900000,

    "duration": 2,

    "dst_port": 4444,

    "src_ip": "192.168.1.10",

    "dst_ip": "192.168.1.20"

}

response = requests.post(
    url,
    json=data
)

print(response.json())