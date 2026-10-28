import time
import json
import os
from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table

console = Console()
KNOWN_DEVICES_FILE = "known_devices.json"

def load_known_devices():
	if os.path.exists(KNOWN_DEVICES_FILE):
		with open(KNOWN_DEVICES_FILE, "r") as f:
			return json.load(f)
	return {}

def scan_network(ip_range="192.168.1.1/24"):
	console.print(f"[bold cyan][*] Scanning subnet {ip_range}...[/bold cyan]")

	arp_request = ARP(pdst=ip_range)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = broadcast / arp_request

	answered_list = srp(packet, timeout=2, verbose=False)[0]

	discovered_devices = []
	for element in answered_list:
		device_info = {
			"ip": element[1].psrc,
			"mac": element[1].hwsrc.upper()
		}
		discovered_devices.append(device_info)
	return discovered_devices

def display_results(devices, known_devices):
	table = Table(title="WiFi Network Access Monitor", style="bold blue")
	table.add_column("IP Address", style="cyan")
	table.add_column("MAC Address", style="magenta")
	table.add_column("Status", style="bold")
	table.add_column("Device Name", style="yellow")

	for dev in devices:
		mac = dev["mac"]
		ip = dev["ip"]

		if mac in known_devices:
			status = "[green]AUTHORIZED[/green]"
			name = known_devices[mac]
		else:
			status = "[bold red] UNKNOWN DEVICE[/bold red]"
			name = "Unrecognized"

		table.add_row(ip, mac, status, name)

	console.print(table)

if __name__ == "__main__":
	known_devices = load_known_devices()

	# VirtualBox NAT networks usually use "10.0.2.1/24"
	# Bridge adapter mode usually uses "192.168.1.1/24" or "192.168.0.1/24"
	target_subnet = "10.0.2.1/24"
	
	discovered = scan_network(target_subnet)
	display_results(discovered, known_devices)
