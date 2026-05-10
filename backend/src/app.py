import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

import resource
import joblib
import pandas as pd
import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import hashlib

# Raise the open-file-descriptor limit to 4096 (macOS default is 256)
_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
resource.setrlimit(resource.RLIMIT_NOFILE, (min(4096, _hard), _hard))

app = Flask(__name__)
CORS(app)

model_detect_anomaly = joblib.load('anomaly_model.pkl')
model_detect_type_anomaly = joblib.load('anomaly_type_model.pkl')

PASSWORD_FILE = "password.hash"

def hash_password(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message: The API is running!"})

@app.route("/detect_anomaly", methods=["POST"])
def detect_anomaly():
    try:
        data = request.json
        input_convert = pd.DataFrame(data)
        predictions = model_detect_anomaly.predict(input_convert)
        return jsonify({"status": "Success",
                        "predictions": [int(p) for p in predictions]})
    except Exception as e:
        return jsonify({"status": "Error",
                       "message": str(e)}), 400
    

ATTACK_LABEL = {
    0: "Normal Communication",
    1: "DDoS Attack",
    2: "Malware Infection",
    3: "Anomaly/Unusual Behavior",
}

# snake_case keys from server.js → Title Case keys the model was trained with
_COL_MAP = {
    "packet_size":               "Packet Size",
    "transmission_rate":         "Transmission Rate",
    "signal_strength":           "Signal Strength",
    "error_rate":                "Error Rate",
    "response_time":             "Response Time",
    "battery_level":             "Battery Level",
    "packet_loss_rate":          "Packet Loss Rate",
    "connection_duration":       "Connection Duration",
    "round_trip_time":           "Round Trip Time",
    "hop_count":                 "Hop Count",
    "jitter":                    "Jitter",
    "drone_velocity":            "Drone Velocity",
    "signal_to_noise_ratio":     "Signal-to-Noise Ratio",
    "data_throughput":           "Data Throughput",
    "communication_interval":    "Communication Interval",
    "control_command_frequency": "Control Command Frequency",
    "drone_altitude":            "Drone Altitude",
    "cpu_usage":                 "CPU Usage",
    "memory_utilization":        "Memory Utilization",
    "distance_to_base_station":  "Distance to Base Station",
    "protocol_type":             "Protocol Type",
    "payload_type":              "Payload Type",
    "encryption_status":         "Encryption Status",
}

@app.route("/detect_type_anomaly", methods=["POST"])
def detect_type_anomaly():
    try:
        data = request.json
        input_convert = pd.DataFrame(data).rename(columns=_COL_MAP)
        raws = model_detect_type_anomaly.predict(input_convert)
        labels = [ATTACK_LABEL.get(int(r), "Unknown") for r in raws]
        return jsonify({"status": "Success",
                        "predictions": labels})
    except Exception as e:
        return jsonify({"status": "Error",
                        "message": str(e)}), 400
    

# ================= CHECK PASSWORD =================
@app.route("/login", methods=["POST"])
def login():
    # Check if password file exists
    if not os.path.exists(PASSWORD_FILE):
        return jsonify({"error": "Password not set"}), 400

    # Extract password string from JSON
    password = request.json.get("password")
    if not password:
        return jsonify({"error": "Password missing"}), 400

    hashed_input = hash_password(password)

    with open(PASSWORD_FILE, "r") as f:
        saved = f.read().strip()  # remove any extra whitespace/newline

    if hashed_input == saved:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "failed"}), 401

            
# ================= SET-UP PASSWORD =================
@app.route("/set_up", methods=["POST"])
def set_up():
    if os.path.exists(PASSWORD_FILE):
        return jsonify({"message": "Password already set"}), 403
    password = request.json["password"]
    hashed = hash_password(password)

    with open(PASSWORD_FILE, "w") as f:
        f.write(hashed)
    return jsonify({"message": "Password created"})



if __name__ == "__main__":
    app.run(port=8000, debug=True)

    