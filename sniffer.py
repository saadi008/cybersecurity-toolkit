
from scapy.all import *
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket

# ---------------- LOGIN ----------------
USERNAME = "admin"
PASSWORD = "1234"

def check_login():
    if user_entry.get() == USERNAME and pass_entry.get() == PASSWORD:
        login_frame.destroy()
        main_app()
    else:
        messagebox.showerror("Error", "Invalid Credentials")

# ---------------- GLOBALS ----------------
sniffing = False
packet_count = 0
http_count = 0

# ---------------- SNIFFER ----------------
def process_packet(packet):
    global packet_count, http_count

    if packet.haslayer(IP):
        packet_count += 1
        ip = packet[IP]
        log = f"[IP] {ip.src} -> {ip.dst}\n"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            log += f"[TCP] {tcp.sport} -> {tcp.dport}\n"

            # HTTP filter
            if tcp.dport == 80 or tcp.sport == 80:
                http_count += 1
                log += "[HTTP] Detected\n"

                # Website Tracker
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if b"Host:" in payload:
                        try:
                            host = payload.split(b"Host: ")[1].split(b"\r\n")[0]
                            log += f"[Website] {host.decode()}\n"
                        except:
                            pass

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            log += f"[UDP] {udp.sport} -> {udp.dport}\n"

        log += "-" * 40 + "\n"

        sniffer_output.insert(tk.END, log)
        sniffer_output.yview(tk.END)

        # Update Dashboard
        stats_label.config(text=f"Packets: {packet_count} | HTTP: {http_count}")

        # Save logs
        with open("logs.txt", "a") as f:
            f.write(log)


def start_sniffing():
    global sniffing
    sniffing = True

    def sniff_thread():
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing)

    threading.Thread(target=sniff_thread, daemon=True).start()


def stop_sniffing():
    global sniffing
    sniffing = False


# ---------------- PORT SCANNER ----------------
def scan_ports():
    target = port_entry.get()
    port_output.delete(1.0, tk.END)

    def scan():
        for port in range(1, 200):  # reduced range
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)  # faster timeout
                result = sock.connect_ex((target, port))

                if result == 0:
                    port_output.insert(tk.END, f"[OPEN] Port {port}\n")

                sock.close()
            except:
                pass

    threading.Thread(target=scan, daemon=True).start()


# ---------------- DNS ----------------
def dns_lookup():
    domain = dns_entry.get()
    try:
        ip = socket.gethostbyname(domain)
        dns_output.delete(1.0, tk.END)
        dns_output.insert(tk.END, f"{domain} -> {ip}")
    except:
        dns_output.insert(tk.END, "Error")


# ---------------- MAIN APP ----------------
def main_app():
    global sniffer_output, stats_label, port_entry, port_output, dns_entry, dns_output

    root = tk.Tk()
    root.title("Cyber Toolkit PRO")
    root.geometry("900x600")

    tabs = ttk.Notebook(root)
    tabs.pack(fill="both", expand=True)

    # -------- SNIFFER --------
    tab1 = tk.Frame(tabs)
    tabs.add(tab1, text="Sniffer")

    stats_label = tk.Label(tab1, text="Packets: 0 | HTTP: 0")
    stats_label.pack()

    sniffer_output = scrolledtext.ScrolledText(tab1, bg="black", fg="lime")
    sniffer_output.pack(fill=tk.BOTH, expand=True)

    btn_frame = tk.Frame(tab1)
    btn_frame.pack()

    tk.Button(btn_frame, text="Start", command=start_sniffing, bg="green").pack(side=tk.LEFT, padx=10)
    tk.Button(btn_frame, text="Stop", command=stop_sniffing, bg="red").pack(side=tk.LEFT)

    # -------- PORT SCANNER --------
    tab2 = tk.Frame(tabs)
    tabs.add(tab2, text="Port Scanner")

    tk.Label(tab2, text="Target IP:").pack()
    port_entry = tk.Entry(tab2)
    port_entry.pack()

    tk.Button(tab2, text="Scan", command=scan_ports).pack()

    port_output = scrolledtext.ScrolledText(tab2)
    port_output.pack(fill=tk.BOTH, expand=True)

    # -------- DNS --------
    tab3 = tk.Frame(tabs)
    tabs.add(tab3, text="DNS")

    tk.Label(tab3, text="Domain:").pack()
    dns_entry = tk.Entry(tab3)
    dns_entry.pack()

    tk.Button(tab3, text="Resolve", command=dns_lookup).pack()

    dns_output = scrolledtext.ScrolledText(tab3)
    dns_output.pack(fill=tk.BOTH, expand=True)

    root.mainloop()


# ---------------- LOGIN UI ----------------
root = tk.Tk()
root.title("Login")

login_frame = tk.Frame(root)
login_frame.pack(pady=100)

tk.Label(login_frame, text="Username").pack()
user_entry = tk.Entry(login_frame)
user_entry.pack()

tk.Label(login_frame, text="Password").pack()
pass_entry = tk.Entry(login_frame, show="*")
pass_entry.pack()

tk.Button(login_frame, text="Login", command=check_login).pack(pady=10) 

root.mainloop()         