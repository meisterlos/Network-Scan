from scapy.all import ARP, Ether, srp
from colorama import Fore, init
import time
import requests
import socket
import ipaddress
from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure

# Colorama'yı başlat
init(autoreset=True)

def scan_network(network, timeout=10, retries=3):
    devices = []
    for _ in range(retries):
        # Burada Arp isteklerini oluşturup taratıyorum.
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request

        # Ağı tarama ve yanıtları al
        answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]

        # Yanıtları işleme
        for element in answered_list:
            device_info = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc
            }
            if device_info not in devices:
                devices.append(device_info)

        # Tarama sonuçlarını kontrol et
        if devices:
            break
        else:
            print(Fore.RED + "Cihazlar bulunamadı, tekrar deniyor...")
            time.sleep(10)  # Tekrar denemeden önce daha uzun bir bekleme süresi

    return devices

def print_devices(devices):
    # Renkli IP ve MAC adreslerini yazdır
    print(Fore.GREEN + "IP Address           MAC Address           Vendor                       Ports               SMB Share")
    print(Fore.GREEN + "=" * 80)
    if devices:
        for device in devices:
            vendor = get_vendor(device['mac'])
            open_ports = scan_ports(device['ip'])
            smb_status, smb_shares = check_smb_share(device['ip'])
            smb_shares_str = ", ".join(smb_shares)  
            smb_share_output = f"{Fore.RED}{smb_status}"
            if smb_shares:
                smb_share_output += f" ({Fore.GREEN}{smb_shares_str})"

            print(f"{Fore.CYAN}{device['ip']:20} {Fore.YELLOW}{device['mac']:20} {Fore.BLUE}{vendor:30} {Fore.MAGENTA}{open_ports:20} {smb_share_output}")
    else:
        print(Fore.RED + "Ağ taramasında cihaz bulunamadı.")

def get_vendor(mac):
 
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    url = f"https://api.macvendors.com/{oui}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except requests.RequestException as e:
        print(f"API isteği sırasında bir hata oluştu: {e}")
        return "Unknown Vendor"

def scan_ports(ip, ports=None):
    if ports is None:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 3306, 5432, 5900, 6379, 27017, 8080, 8000, 8081, 8443, 8888]  # Popüler portlar

    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    
    return ', '.join(map(str, open_ports)) if open_ports else "No open ports"

def check_smb_share(ip):
    # Port 445 üzerinde SMB paylaşımı olup olmadığını kontrol ediyor.
    smb_shares = []
    try:
        conn = SMBConnection('', '', '', '', use_ntlm_v2=True)
        conn.connect(ip, 445, timeout=7)  
        shares = conn.listShares()
        if shares:
            smb_shares = [share.name for share in shares]
            return "SMB Share Found", smb_shares
        else:
            return "No SMB Share", []
    except OperationFailure as e:
        print(f"SMB bağlantısı sırasında bir hata oluştu: {e}")
        return "No SMB Share", []
    except Exception as e:
        return "No SMB Share", []  

def is_ip_in_network(ip, network):
    try:
        ip_addr = ipaddress.ip_address(ip)
        network_addr = ipaddress.ip_network(network, strict=False)
        return ip_addr in network_addr
    except ValueError:
        return False

def main():

    network = input(Fore.GREEN + "Tarama yapılacak ağ adresini ve alt ağ maskesini girin (örneğin, 192.168.1.0/24): ")
    
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        print(Fore.RED + "Geçersiz ağ adresi veya alt ağ maskesi.")
        return
    
    devices = scan_network(network)
    devices = [device for device in devices if is_ip_in_network(device['ip'], network)]
    print_devices(devices)

if __name__ == "__main__":
    main()
