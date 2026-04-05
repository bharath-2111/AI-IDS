from scapy.all import sniff, IP, TCP, UDP
import threading
import time
import torch
import os,sys
import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

#backend model paths
MODEL_DIR = os.path.join(BASE_DIR, "models")
WEIGHTS_DIR = os.path.join(MODEL_DIR, "weights")
ENCODERS_DIR = os.path.join(MODEL_DIR, "encoders")


from config import Config
from models.model import Agent


class Sniffer:
    def __init__(self, emit_fun, iface=None, search_ip=None):
        self.iface      = iface
        self.search_ip  = search_ip
        self.emit_fun   = emit_fun
        self.running    = False
        self.thread     = None
        self.timeout    = 10
        self.MIN_PACKETS = 5
        self.MAX_IDLE   = 30
        self.flows      = {}
        self.flow_lock  = threading.Lock()

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        checkpoint  = torch.load(os.path.join(WEIGHTS_DIR,"ai_ids_micro.pth"), map_location=self.device)

        self.model = Agent(checkpoint["inp_size"], checkpoint["num_classes"]).to(self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()

       
        self.temperature = checkpoint["temperature"].cpu()

        self.scaler        = joblib.load(os.path.join(ENCODERS_DIR,"scaler.pkl"))
        self.classes       = joblib.load(os.path.join(ENCODERS_DIR,"classes.pkl"))
        self.proto_encoder = joblib.load(os.path.join(ENCODERS_DIR,"protocol_encoder.pkl"))

        # Per-class thresholds tuned on val set (saves from 25k → 4k false positives)
        self.class_thresholds = joblib.load(os.path.join(ENCODERS_DIR,"class_thresholds.pkl"))

    # Start 

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.thread  = threading.Thread(target=self.sniff_logic, daemon=True)
            self.thread.start()
            print("Sniffing Started")
    # STOP
    def end_sniffing(self):
        self.running = False
        print("Stopping sniffing...")
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        print("Sniffing Stopped")

    # Main loop 

    def sniff_logic(self):
        while self.running:
            kwargs = dict(iface=self.iface, prn=self.process_packets, store=False, timeout=1)
            if self.search_ip:
                kwargs["filter"] = f"host {self.search_ip}"
            sniff(**kwargs)

            # Expiry check + prediction happen OUTSIDE sniff — no packet loss
            results = self.check_expiry()
            for r in results:
                self.emit_fun("predictions", r)

    #  Packet ingestion 

    def process_packets(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip       = pkt[IP]
        proto_num = ip.proto

       
        # Pass the raw integer directly — unknown protos fall back to 0
        known = set(self.proto_encoder.classes_)
        proto_enc = (
            int(self.proto_encoder.transform([proto_num])[0])
            if proto_num in known else 0
        )

        if pkt.haslayer(TCP):
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        else:
            return

        # Canonical flow key: always (lower_end, higher_end)
        if (ip.src, src_port) < (ip.dst, dst_port):
            flow_key, direction = (ip.src, ip.dst, src_port, dst_port, proto_num), "fwd"
        else:
            flow_key, direction = (ip.dst, ip.src, dst_port, src_port, proto_num), "bwd"

        now = time.time()

        with self.flow_lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    "start_time"    : now,
                    "last_seen"     : now,
                    "fwd_packets"   : 0,
                    "bwd_packets"   : 0,
                    "fwd_bytes"     : 0,
                    "bwd_bytes"     : 0,
                    "fwd_pkt_lengths": [],
                    "bwd_pkt_lengths": [],
                    "fwd_timestamps": [],
                    "bwd_timestamps": [],
                    "last_fwd_time" : None,
                    "last_bwd_time" : None,
                    "syn_count"     : 0,
                    "ack_count"     : 0,
                    "fin_count"     : 0,
                    "rst_count"     : 0,
                    "psh_count"     : 0,
                    "proto_enc"     : proto_enc,
                }

            flow = self.flows[flow_key]
            flow["last_seen"] = now

            pkt_len = len(pkt)
            if direction == "fwd":
                flow["fwd_packets"] += 1
                flow["fwd_bytes"]   += pkt_len
                flow["fwd_pkt_lengths"].append(pkt_len)
                if flow["last_fwd_time"] is not None:
                    flow["fwd_timestamps"].append(now - flow["last_fwd_time"])
                flow["last_fwd_time"] = now
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"]   += pkt_len
                flow["bwd_pkt_lengths"].append(pkt_len)
                if flow["last_bwd_time"] is not None:
                    flow["bwd_timestamps"].append(now - flow["last_bwd_time"])
                flow["last_bwd_time"] = now

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x02: flow["syn_count"] += 1
                if flags & 0x10: flow["ack_count"] += 1
                if flags & 0x01: flow["fin_count"]  += 1
                if flags & 0x04: flow["rst_count"]  += 1
                if flags & 0x08: flow["psh_count"]  += 1

    # Flow expiry -> snapshot then release lock before inference 

    def check_expiry(self):
        now      = time.time()
        to_infer = []  
        expired  = []

        # identify expired flows and snapshot them — lock held briefly
        with self.flow_lock:
            for key in list(self.flows.keys()):
                flow         = self.flows[key]
                total_pkts   = flow["fwd_packets"] + flow["bwd_packets"]
                idle         = now - flow["last_seen"]

                if (total_pkts >= self.MIN_PACKETS and idle > self.timeout) or idle > self.MAX_IDLE:
                    to_infer.append((key, dict(flow)))   
                    expired.append(key)

            for key in expired:
                del self.flows[key]

        #run inference OUTSIDE the lock — process_packets never blocked
        results = []
        for key, flow_snap in to_infer:
            features = self.extract_features(flow_snap, key[4])
            results.append(self.predict_flow(key[0], key[1], features))

        return results

    #Feature extraction

    def extract_features(self, flow, proto_num):
        duration        = max(flow["last_seen"] - flow["start_time"], 1e-6)
        total_fwd       = flow["fwd_packets"]
        total_bwd       = flow["bwd_packets"]
        total_fwd_bytes = flow["fwd_bytes"]
        total_bwd_bytes = flow["bwd_bytes"]
        total_packets   = total_fwd + total_bwd
        total_bytes     = total_fwd_bytes + total_bwd_bytes

        all_pkts     = flow["fwd_pkt_lengths"] + flow["bwd_pkt_lengths"]
        all_iat      = flow["fwd_timestamps"]  + flow["bwd_timestamps"]

        def safe_mean(lst): return float(np.mean(lst)) if lst else 0.0
        def safe_std(lst):  return float(np.std(lst))  if lst else 0.0
        def safe_max(lst):  return float(np.max(lst))  if lst else 0.0
        def safe_min(lst):  return float(np.min(lst))  if lst else 0.0

        feature_dict = {
            "Protocol"          : flow["proto_enc"],
            "Flow Duration"     : duration,
            "Tot Fwd Pkts"      : total_fwd,
            "Tot Bwd Pkts"      : total_bwd,
            "TotLen Fwd Pkts"   : total_fwd_bytes,
            "TotLen Bwd Pkts"   : total_bwd_bytes,
            "Fwd Pkt Len Mean"  : safe_mean(flow["fwd_pkt_lengths"]),
            "Bwd Pkt Len Mean"  : safe_mean(flow["bwd_pkt_lengths"]),
            "Pkt Len Mean"      : safe_mean(all_pkts),
            "Pkt Len Std"       : safe_std(all_pkts),
            "Pkt Len Max"       : safe_max(all_pkts),
            "Pkt Len Min"       : safe_min(all_pkts),
            "Flow Byts/s"       : total_bytes   / duration,
            "Flow Pkts/s"       : total_packets / duration,
            "Fwd Pkts/s"        : total_fwd     / duration,
            "Bwd Pkts/s"        : total_bwd     / duration,
            "Flow IAT Mean"     : safe_mean(all_iat),
            "Flow IAT Std"      : safe_std(all_iat),
            "Fwd IAT Mean"      : safe_mean(flow["fwd_timestamps"]),
            "Bwd IAT Mean"      : safe_mean(flow["bwd_timestamps"]),
            "SYN Flag Cnt"      : flow["syn_count"],
            "ACK Flag Cnt"      : flow["ack_count"],
            "FIN Flag Cnt"      : flow["fin_count"],
            "RST Flag Cnt"      : flow["rst_count"],
            "PSH Flag Cnt"      : flow["psh_count"],
            "Down/Up Ratio"     : total_bwd / total_fwd if total_fwd > 0 else 0.0,
        }

        return [feature_dict[col] for col in Config.FEATURES]

    #  Prediction with per-class thresholds

    def predict_flow(self, src_ip, dst_ip, features):
        x        = pd.DataFrame([features], columns=Config.FEATURES)
        x_scaled = self.scaler.transform(x)
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32).to(self.device)

        with torch.no_grad():
            # temperature is on CPU; move to device only for this division
            logits = self.model(x_tensor) / self.temperature.to(self.device)
            probs  = torch.softmax(logits, dim=1).cpu().numpy()[0]  # (num_classes,)

        pred_class_idx = int(np.argmax(probs))
        confidence     = float(probs[pred_class_idx])
        predicted_class = self.classes[pred_class_idx]

        # Use the per-class threshold tuned on val set
        class_threshold = float(self.class_thresholds[pred_class_idx])

        if confidence < class_threshold:
            decision = "Unknown"
        elif predicted_class == "Benign":
            decision = "Normal"
        else:
            decision = "Malicious"

        return {
            "src_ip"    : src_ip,
            "dst_ip"    : dst_ip,
            "Class"     : predicted_class,
            "Confidence": round(confidence, 4),
            "Threshold" : round(class_threshold, 2),
            "Decision"  : decision,
        }