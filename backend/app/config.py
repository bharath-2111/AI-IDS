import os

class Config:
   # IFACE = r'\Device\NPF_{66438D3D-E0FD-4DC4-A573-CBA94AC78FBF}'
    IFACE = 'enp0s8'
    CORS_ORIGINS = "*"
    DEBUG = False
    FEATURES = [
        'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
        'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Mean',
        'Bwd Pkt Len Mean', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Max',
        'Pkt Len Min', 'Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Mean', 'Bwd IAT Mean',
        'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 'RST Flag Cnt',
        'PSH Flag Cnt', 'Down/Up Ratio',
    ]