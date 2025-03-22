import tkinter as tk
from tkinter import ttk
from scapy.all import *
import os
import subprocess

def set_monitor_mode(iface):
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "monitor", "promisc"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error setting monitor mode: {e}")

def reset_interface(iface):
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error resetting interface: {e}")

def scan_wifi():
    networks = []
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            if ssid not in [network['SSID'] for network in networks]:
                networks.append({'SSID': ssid, 'BSSID': bssid})
                tree.insert("", "end", values=(ssid, bssid))

    try:
        iface = "en0"  # Change this to the correct interface name
        set_monitor_mode(iface)
        sniff(prn=packet_handler, iface=iface, timeout=10)
        reset_interface(iface)
    except Exception as e:
        print(f"Error: {e}")

def start_scan():
    tree.delete(*tree.get_children())
    scan_wifi()

# Create the main window
root = tk.Tk()
root.title("Wi-Fi Scanner")

# Create a treeview to display the networks
tree = ttk.Treeview(root, columns=("SSID", "BSSID"), show="headings")
tree.heading("SSID", text="SSID")
tree.heading("BSSID", text="BSSID")
tree.pack(fill=tk.BOTH, expand=True)

# Create a button to start the scan
scan_button = tk.Button(root, text="Scan Wi-Fi", command=start_scan)
scan_button.pack(pady=10)

# Run the application
root.mainloop()