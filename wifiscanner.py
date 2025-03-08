import tkinter as tk
from tkinter import ttk
from scapy.all import *

def scan_wifi():
    networks = []
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            if ssid not in [network['SSID'] for network in networks]:
                networks.append({'SSID': ssid, 'BSSID': bssid})
                tree.insert("", "end", values=(ssid, bssid))

    async_sniff(prn=packet_handler, iface="en0", timeout=10)

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