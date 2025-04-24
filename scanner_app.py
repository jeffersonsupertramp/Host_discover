
import customtkinter as ctk
import socket
import threading
import ipaddress
import nmap
import tkinter as tk
from tkinter import ttk
import webbrowser
import re
import urllib.request

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class ScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.iconbitmap("capa.png")
        self.title("Host Discovery")
        self.geometry("900x600")
        self.scanning = False
        self.auto_detected_range = None

        self._setup_ui()
        self.update_machine_info_label()
    
    def _setup_ui(self):
        """Initialize the UI components."""
        self.button_auto_host_discovery = ctk.CTkButton(self, text="Auto Host Discovery", command=self.start_auto_host_discovery)
        self.button_auto_host_discovery.pack(pady=10)

        self.label_additional_ranges = ctk.CTkLabel(self, text="Additional IP Ranges (one per line, format: start_ip-end_ip):")
        self.label_additional_ranges.pack(pady=(10, 0), padx=20)

        self.text_additional_ranges = ctk.CTkTextbox(self, width=600, height=100)
        self.text_additional_ranges.pack(padx=20, pady=5)

        self.button_scan_all = ctk.CTkButton(self, text="Start Scan All", command=self.start_scan_all)
        self.button_scan_all.pack(pady=10)

        self.label_host_scan = ctk.CTkLabel(self, text="Enter Host to Scan Ports (IP or Hostname):")
        self.label_host_scan.pack(pady=(20, 5))

        self.entry_host_scan = ctk.CTkEntry(self, width=300)
        self.entry_host_scan.pack(pady=5)

        self.button_scan_host_ports = ctk.CTkButton(self, text="Scan Ports of Host", command=self.start_scan_host_ports)
        self.button_scan_host_ports.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="")
        self.status_label.pack(pady=5)

        self.label_machine_info = ctk.CTkLabel(self, text="Machine Info: Loading...")
        self.label_machine_info.pack(pady=(0, 10))

        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.pack(padx=20, pady=10, fill="both", expand=True)

        self.tree = ttk.Treeview(self.table_frame, columns=("IP", "MAC", "Vendor", "OS", "Web Access"), show="headings")
        self.tree.heading("IP", text="IP")
        self.tree.heading("MAC", text="MAC")
        self.tree.heading("Vendor", text="Vendor")
        self.tree.heading("OS", text="OS")
        self.tree.heading("Web Access", text="Web Access")
        self.tree.column("IP", width=120)
        self.tree.column("MAC", width=150)
        self.tree.column("Vendor", width=150)
        self.tree.column("OS", width=150)
        self.tree.column("Web Access", width=200)
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Double-1>", self.on_double_click)

    def update_machine_info_label(self):
        """Fetch and update the machine hostname and external IP asynchronously."""
        def fetch_and_update():
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "Unknown Hostname"

            try:
                with urllib.request.urlopen('https://api.ipify.org') as response:
                    external_ip = response.read().decode('utf-8')
            except Exception:
                external_ip = "Unknown External IP"

            info_text = f"Machine: {hostname} | External IP: {external_ip}"
            self.label_machine_info.configure(text=info_text)

        threading.Thread(target=fetch_and_update, daemon=True).start()



import socket
import threading
import ipaddress
import nmap
import tkinter as tk
from tkinter import ttk
import webbrowser
import re
import urllib.request

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class ScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Host Discovery")
        self.geometry("900x600")
        self.scanning = False
        self.auto_detected_range = None

        self._setup_ui()
        self.update_machine_info_label()

    def _setup_ui(self):
        """Initialize the UI components."""
        self.button_auto_host_discovery = ctk.CTkButton(self, text="Auto Host Discovery", command=self.start_auto_host_discovery)
        self.button_auto_host_discovery.pack(pady=10)

        self.label_additional_ranges = ctk.CTkLabel(self, text="Additional IP Ranges (one per line, format: start_ip-end_ip):")
        self.label_additional_ranges.pack(pady=(10, 0), padx=20)

        self.text_additional_ranges = ctk.CTkTextbox(self, width=600, height=100)
        self.text_additional_ranges.pack(padx=20, pady=5)

        self.button_scan_all = ctk.CTkButton(self, text="Start Scan All", command=self.start_scan_all)
        self.button_scan_all.pack(pady=10)

        self.label_host_scan = ctk.CTkLabel(self, text="Enter Host to Scan Ports (IP or Hostname):")
        self.label_host_scan.pack(pady=(20, 5))

        self.entry_host_scan = ctk.CTkEntry(self, width=300)
        self.entry_host_scan.pack(pady=5)

        self.button_scan_host_ports = ctk.CTkButton(self, text="Scan Ports of Host", command=self.start_scan_host_ports)
        self.button_scan_host_ports.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="")
        self.status_label.pack(pady=5)

        self.label_machine_info = ctk.CTkLabel(self, text="Machine Info: Loading...")
        self.label_machine_info.pack(pady=(0, 10))

        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.pack(padx=20, pady=10, fill="both", expand=True)

        self.tree = ttk.Treeview(self.table_frame, columns=("IP", "MAC", "Vendor", "OS", "Web Access"), show="headings")
        self.tree.heading("IP", text="IP")
        self.tree.heading("MAC", text="MAC")
        self.tree.heading("Vendor", text="Vendor")
        self.tree.heading("OS", text="OS")
        self.tree.heading("Web Access", text="Web Access")
        self.tree.column("IP", width=120)
        self.tree.column("MAC", width=150)
        self.tree.column("Vendor", width=150)
        self.tree.column("OS", width=150)
        self.tree.column("Web Access", width=200)
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Double-1>", self.on_double_click)

        self.label_readme = ctk.CTkLabel(self, text="Todos os direitos reservados Jefferson leo 2025")
        self.label_readme.pack(pady=(0, 10))

    def update_machine_info_label(self):
        """Fetch and update the machine hostname and external IP asynchronously."""
        def fetch_and_update():
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "Unknown Hostname"

            try:
                with urllib.request.urlopen('https://api.ipify.org') as response:
                    external_ip = response.read().decode('utf-8')
            except Exception:
                external_ip = "Unknown External IP"

            info_text = f"Machine: {hostname} | External IP: {external_ip}"
            self.label_machine_info.configure(text=info_text)

        threading.Thread(target=fetch_and_update, daemon=True).start()

    def on_double_click(self, event):
        """Handle double-click events on the treeview to open URLs."""
        tree = event.widget
        selected_item = tree.focus()
        if not selected_item:
            return
        col = tree.identify_column(event.x)
        values = tree.item(selected_item, "values")
        if len(values) < 5:
            return
        if col == '#1':  # IP column
            ip = values[0]
            if ip:
                self.open_url(f"http://{ip}")
        elif col == '#5':  # Web Access column
            web_access = values[4]
            if web_access:
                urls = re.split(r'[,\s]+', web_access.strip())
                for url in urls:
                    if url:
                        self.open_url(url)

    def show_message(self, message):
        """Display a message in the status label."""
        self.status_label.configure(text=message)

    def display_result(self, ip, details):
        """Insert scan results into the treeview."""
        mac = "Unknown"
        vendor = "Unknown"
        os = "Unknown"
        web_access = ""

        for detail in details:
            if detail.startswith("MAC: "):
                mac = detail[5:]
            elif detail.startswith("Vendor: "):
                vendor = detail[8:]
            elif detail.startswith("OS: "):
                os = detail[4:]
            elif detail.startswith("Web: "):
                web_access = detail[5:]

        self.tree.insert("", "end", values=(ip, mac, vendor, os, web_access))

    def open_url(self, url):
        """Open a URL in the default web browser."""
        webbrowser.open(url)

    def start_auto_host_discovery(self):
        """Start automatic host discovery on the local network."""
        if self.scanning:
            self.show_message("Scan already in progress.")
            return

        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ipaddress.ip_network(local_ip + '/24', strict=False)
            self.auto_detected_range = str(network)
        except Exception as e:
            self.show_message(f"Failed to detect local network: {e}")
            return

        self.clear_results()
        self.show_message(f"Starting auto host discovery on network {self.auto_detected_range}...")

        self.scanning = True
        threading.Thread(target=self.auto_host_discovery_scan, args=(self.auto_detected_range,), daemon=True).start()

    def auto_host_discovery_scan(self, ip_range):
        """Perform a ping scan on the given IP range to discover hosts."""
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip_range, arguments='-sn')
            hosts_list = nm.all_hosts()
            for host in hosts_list:
                if not self.scanning:
                    break
                mac = nm[host]['addresses'].get('mac', 'Unknown') if 'addresses' in nm[host] else 'Unknown'
                vendor = nm[host]['vendor'].get(mac, 'Unknown') if 'vendor' in nm[host] else 'Unknown'
                os = 'Unknown'  # OS detection can be added if needed
                web_access = ''  # Placeholder for web access info

                details = [f"MAC: {mac}", f"Vendor: {vendor}", f"OS: {os}", f"Web: {web_access}"]
                self.display_result(host, details)
        except Exception as e:
            self.show_message(f"Auto host discovery scan failed: {e}")
        finally:
            self.scanning = False
            self.show_message("Auto host discovery scan completed.")

    def start_scan_all(self):
        """Start scanning all specified IP ranges."""
        if self.scanning:
            self.show_message("Scan already in progress.")
            return

        additional_ranges = self._parse_additional_ranges()
        if additional_ranges is None:
            return

        ranges_to_scan = []
        if self.auto_detected_range:
            ranges_to_scan.append(self.auto_detected_range)
        ranges_to_scan.extend(additional_ranges)

        if not ranges_to_scan:
            self.show_message("No IP ranges to scan. Please use Auto Host Discovery or enter additional ranges.")
            return

        self.clear_results()
        self.show_message(f"Starting scan on {len(ranges_to_scan)} range(s)...")

        self.scanning = True
        threading.Thread(target=self.scan_multiple_ranges, args=(ranges_to_scan,), daemon=True).start()

    def _parse_additional_ranges(self):
        """Parse additional IP ranges entered by the user."""
        additional_ranges_text = self.text_additional_ranges.get("0.0", ctk.END).strip()
        additional_ranges = []

        if additional_ranges_text:
            for line in additional_ranges_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if '-' not in line:
                    self.show_message(f"Invalid range format: {line}. Expected format: start_ip-end_ip")
                    return None
                start_ip_str, end_ip_str = line.split('-', 1)
                try:
                    start_ip_obj = ipaddress.ip_address(start_ip_str.strip())
                    end_ip_obj = ipaddress.ip_address(end_ip_str.strip())
                    if start_ip_obj > end_ip_obj:
                        self.show_message(f"Start IP must be less than or equal to End IP in range: {line}")
                        return None
                    additional_ranges.append(f"{start_ip_obj}-{end_ip_obj}")
                except ValueError:
                    self.show_message(f"Invalid IP address format in range: {line}")
                    return None
        return additional_ranges

    def scan_multiple_ranges(self, ranges):
        """Scan multiple IP ranges for hosts."""
        nm = nmap.PortScanner()
        try:
            for ip_range in ranges:
                if not self.scanning:
                    break
                self.show_message(f"Scanning network {ip_range}...")
                nm.scan(hosts=ip_range, arguments='-sn')
                hosts_list = nm.all_hosts()
                for host in hosts_list:
                    if not self.scanning:
                        break
                    mac = nm[host]['addresses'].get('mac', 'Unknown') if 'addresses' in nm[host] else 'Unknown'
                    vendor = nm[host]['vendor'].get(mac, 'Unknown') if 'vendor' in nm[host] else 'Unknown'
                    os = 'Unknown'
                    web_access = ''
                    details = [f"MAC: {mac}", f"Vendor: {vendor}", f"OS: {os}", f"Web: {web_access}"]
                    self.display_result(host, details)
        except Exception as e:
            self.show_message(f"Scan failed: {e}")
        finally:
            self.scanning = False
            self.show_message("Scan completed.")

    def clear_results(self):
        """Clear all entries from the results treeview."""
        for i in self.tree.get_children():
            self.tree.delete(i)

    def on_closing(self):
        """Handle application closing event."""
        self.scanning = False
        self.destroy()

    def start_scan_host_ports(self):
        """Start scanning ports of a specific host."""
        if self.scanning:
            self.show_message("Scan already in progress.")
            return

        host = self.entry_host_scan.get().strip()
        if not host:
            self.show_message("Please enter a valid host to scan.")
            return

        self.clear_results()
        self.show_message(f"Starting port scan on host {host}...")

        self.scanning = True
        threading.Thread(target=self.scan_host_ports, args=(host,), daemon=True).start()

    def scan_host_ports(self, host):
        """Scan all ports of the specified host and display open ports."""
        nm = nmap.PortScanner()
        open_ports = []

        try:
            nm.scan(hosts=host, arguments='-p 0-65535 --open')
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            open_ports.append(port)
            else:
                self.show_message(f"No information found for host {host}.")
        except Exception as e:
            self.show_message(f"Port scan failed: {e}")
        finally:
            self.scanning = False

        self.show_open_ports_card(host, open_ports)
        self.show_message(f"Port scan completed for host {host}. Found {len(open_ports)} open ports.")

    def show_open_ports_card(self, host, open_ports):
        """Display a card window showing open ports for the host."""
        card = tk.Toplevel(self)
        card.title(f"Open Ports for {host}")
        card.geometry("400x400")

        label = ctk.CTkLabel(card, text=f"Open Ports for {host}", font=ctk.CTkFont(size=16, weight="bold"))
        label.pack(pady=10)

        if not open_ports:
            no_ports_label = ctk.CTkLabel(card, text="No open ports found.")
            no_ports_label.pack(pady=20)
            return

        ports_frame = ctk.CTkScrollableFrame(card, width=360, height=300)
        ports_frame.pack(padx=10, pady=10, fill="both", expand=True)

        for port in sorted(open_ports):
            port_label = ctk.CTkLabel(ports_frame, text=f"Port {port} is open")
            port_label.pack(anchor="w", pady=2)

if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
