import threading
from app.services.sniff import Sniffer
from app.config import Config

sniffer = None
sniffer_lock = threading.Lock()

def register_socket_events(socketio):

    def _get_or_create_sniffer(search_ip=None):
        global sniffer
        if sniffer is None:
            sniffer = Sniffer(socketio.emit, iface=Config.IFACE, search_ip=search_ip)
        return sniffer

    # SET FILTER
    @socketio.on("set-filter")
    def set_filter(res):
        global sniffer
        with sniffer_lock:
            try:
                _get_or_create_sniffer(search_ip=res)
                sniffer.search_ip = res
            except Exception as e:
                return {"error": f"Failed to initialise sniffer: {str(e)}"}

        print(f"Filter set: {res}")
        return {"status": "filter applied", "ip": res}

    # CLEAR FILTER
    @socketio.on("clear-filter")
    def clear_filter():
        with sniffer_lock:
            if sniffer:
                sniffer.search_ip = None
        return {"status": "filter cleared"}

    # START CAPTURE
    @socketio.on("start-capturing")
    def start_capture(data=None):
        global sniffer
        with sniffer_lock:
            try:
                _get_or_create_sniffer()
            except Exception as e:
                return {"error": f"Failed to initialise sniffer: {str(e)}"}

            if sniffer.running:
                return {"error": "Already sniffing"}

            sniffer.start_sniffing()

        return {
            "status": "sniffing started",
            "iface": Config.IFACE,
            "filter": sniffer.search_ip
        }

    # STOP CAPTURE
    @socketio.on("stop-capturing")
    def stop_capture(data):
        global sniffer
        with sniffer_lock:
            if sniffer is None:
                return {"error": "Sniffer not running"}

            sniffer.end_sniffing()
            sniffer = None

        return {"status": "sniffing stopped"}

    # STATUS
    @socketio.on("status")
    def get_status():
        with sniffer_lock:
            if sniffer is None:
                return {"running": False, "filter": None, "iface": Config.IFACE}

            return {
                "running": sniffer.running,
                "filter": sniffer.search_ip,
                "iface": Config.IFACE,
                "flows": len(sniffer.flows),
            }