import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
from threading import Thread
import psutil

# Global variables to keep track of sniffing status and packet count
sniffing = True
packet_count = 0

# This function handles what happens to each packet we sniff
def packet_callback(packet, output_text):
    global packet_count
    packet_count += 1
    packet_summary = packet.summary()
    
    # Let's figure out the protocol of this packet
    if "ARP" in packet_summary:
        protocol = "ARP (Address Resolution Protocol)"
    elif "TCP" in packet_summary:
        protocol = "TCP (Transmission Control Protocol)"
    elif "UDP" in packet_summary:
        protocol = "UDP (User Datagram Protocol)"
    elif "ICMP" in packet_summary:
        protocol = "ICMP (Internet Control Message Protocol)"
    else:
        protocol = "Unknown Protocol"
    
    # Highlight anything that seems suspicious
    if "who has" in packet_summary and "ARP" in packet_summary:
        packet_summary = f"[SUSPICIOUS] {packet_summary}"
        output_text.tag_configure("suspicious", foreground="green")
        output_text.insert(tk.END, f"{packet_summary} ({protocol})\n", "suspicious")
    else:
        output_text.insert(tk.END, f"{packet_summary} ({protocol})\n")
    
    output_text.see(tk.END)

# Function to start sniffing packets
def start_sniffing(interface, output_text, status_label):
    global sniffing
    sniffing = True
    status_label.config(text="Sniffing in progress...", foreground="green")
    sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, output_text), store=0, stop_filter=lambda x: not sniffing)

# This is just to kick off the sniffing in a separate thread so the UI stays responsive
def start_sniffing_thread(interface, output_text, status_label):
    sniff_thread = Thread(target=start_sniffing, args=(interface, output_text, status_label))
    sniff_thread.daemon = True
    sniff_thread.start()

# Function to stop sniffing packets
def stop_sniffing(status_label):
    global sniffing
    sniffing = False
    status_label.config(text="Sniffing stopped", foreground="red")

# Show a summary of what we’ve sniffed so far and some security tips
def show_summary():
    summary_text = f"Total packets sniffed: {packet_count}\n\n"
    summary_text += "Things you should check:\n"
    summary_text += "- Keep an eye on frequent ARP requests (could be ARP spoofing).\n"
    summary_text += "- Analyze any weird IPs communicating with your network.\n"
    summary_text += "- Watch out for unexpected protocol activities (like ICMP messages).\n"
    summary_text += "- Ensure only authorized devices are connected to your network.\n"
    
    summary_text += "\nSecurity tips:\n"
    summary_text += "- Use strong, complex passwords for all network devices.\n"
    summary_text += "- Keep your systems and software up to date.\n"
    summary_text += "- Use a firewall and IDS/IPS to monitor your network.\n"
    summary_text += "- Disable unused network services and ports.\n"

    summary_window = tk.Toplevel(root)
    summary_window.title("Summary and Security Tips")
    summary_window.geometry("400x300")
    summary_label = tk.Label(summary_window, text=summary_text, justify=tk.LEFT)
    summary_label.pack(pady=10, padx=10)

# Function to get a list of network interfaces available on the system
def get_network_interfaces():
    interfaces = psutil.net_if_addrs().keys()
    return list(interfaces)

# Setting up the GUI
root = tk.Tk()
root.title("Professional Firewall Simulation")
root.geometry("800x600")
root.configure(bg="#2e3f4f")

# Interface selection using a dropdown menu
interface_frame = tk.Frame(root, bg="#2e3f4f")
interface_frame.pack(pady=10)

interface_label = tk.Label(interface_frame, text="Select an Interface:", bg="#2e3f4f", fg="white")
interface_label.pack(side=tk.LEFT, padx=5)

interfaces = get_network_interfaces()
interface_combobox = ttk.Combobox(interface_frame, values=interfaces)
interface_combobox.pack(side=tk.LEFT, padx=5)
interface_combobox.set(interfaces[0])  # Default to the first interface in the list

# Start, Stop, and Status controls
control_frame = tk.Frame(root, bg="#2e3f4f")
control_frame.pack(pady=10)

start_button = tk.Button(control_frame, text="Start Sniffing", bg="#4caf50", fg="white",
                         command=lambda: start_sniffing_thread(interface_combobox.get(), output_text, status_label))
start_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(control_frame, text="Stop Sniffing", bg="#f44336", fg="white",
                        command=lambda: stop_sniffing(status_label))
stop_button.pack(side=tk.LEFT, padx=10)

status_label = tk.Label(control_frame, text="Ready", bg="#2e3f4f", fg="white")
status_label.pack(side=tk.LEFT, padx=10)

# Output window with scrollbar
output_frame = tk.Frame(root)
output_frame.pack(pady=10, fill=tk.BOTH, expand=True)

output_text = tk.Text(output_frame, wrap=tk.WORD, height=20, bg="#1c2833", fg="white", insertbackground="white")
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=output_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output_text.config(yscrollcommand=scrollbar.set)

# Section explaining the protocols and suspicious activity markers
explanation_label = tk.Label(root, text="Explanation of protocols and suspicious activities:", 
                             bg="#2e3f4f", fg="white", anchor="w")
explanation_label.pack(fill=tk.X, padx=10)

explanation_text = tk.Text(root, wrap=tk.WORD, height=5, bg="#1c2833", fg="white", insertbackground="white")
explanation_text.pack(pady=5, padx=10, fill=tk.X)
explanation_text.insert(tk.END, "ARP: Address Resolution Protocol\n"
                                "TCP: Transmission Control Protocol\n"
                                "UDP: User Datagram Protocol\n"
                                "ICMP: Internet Control Message Protocol\n"
                                "Suspicious activities: Highlighted in green")
explanation_text.config(state=tk.DISABLED)

# Button to show the summary
summary_button = tk.Button(root, text="Show Summary", bg="#2196f3", fg="white",
                           command=show_summary)
summary_button.pack(pady=10)

root.mainloop()
