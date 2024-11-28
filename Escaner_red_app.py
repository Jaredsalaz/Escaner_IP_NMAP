import tkinter as tk
from tkinter import messagebox, simpledialog
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from mac_vendor_lookup import MacLookup

# Diccionario de puertos y sus servicios comunes
puertos_servicios = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

def escanear_red(rango_ip):
    arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp
    resultado = srp(paquete, timeout=3, verbose=0)[0]
    dispositivos = [{'ip': recibido.psrc, 'mac': recibido.hwsrc} for enviado, recibido in resultado]
    return dispositivos

def escanear_puertos(ip, puertos):
    puertos_abiertos = []
    for puerto in puertos:
        pkt = IP(dst=ip)/TCP(dport=puerto, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is not None and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            puertos_abiertos.append(puerto)
            sr1(IP(dst=ip)/TCP(dport=puerto, flags="R"), timeout=1, verbose=0)
    return puertos_abiertos

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Red echo por Jared")
        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self.root, text="Rango de IPs a escanear:")
        self.label.pack(pady=5)
        self.entry = tk.Entry(self.root)
        self.entry.pack(pady=5)
        self.entry.insert(0, "192.168.1.0/24")
        self.scan_button = tk.Button(self.root, text="Escanear Red", command=self.scan_network)
        self.scan_button.pack(pady=5)
        self.result_text = tk.Text(self.root, height=15, width=80)
        self.result_text.pack(pady=5)

    def scan_network(self):
        rango_ip = self.entry.get()
        dispositivos = escanear_red(rango_ip)
        mac_lookup = MacLookup()
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Dispositivos encontrados en la red:\n")
        self.result_text.insert(tk.END, "ID  IP" + " "*18 + "MAC" + " "*18 + "Fabricante\n")
        for idx, dispositivo in enumerate(dispositivos):
            try:
                fabricante = mac_lookup.lookup(dispositivo['mac'])
            except KeyError:
                fabricante = "Desconocido"
            self.result_text.insert(tk.END, f"{idx+1:2}  {dispositivo['ip']:16}    {dispositivo['mac']:17}    {fabricante}\n")
        if dispositivos:
            self.select_device(dispositivos)

    def select_device(self, dispositivos):
        seleccion = simpledialog.askinteger("Seleccionar IP", "Selecciona el ID de la IP que deseas escanear los puertos:")
        if seleccion is not None and 1 <= seleccion <= len(dispositivos):
            ip_seleccionada = dispositivos[seleccion-1]['ip']
            self.scan_ports(ip_seleccionada)

    def scan_ports(self, ip):
        opcion = simpledialog.askinteger("Opciones de escaneo", "1. Escanear puertos más vulnerables (backdoors)\n2. Escanear un rango específico de puertos\nSelecciona una opción:")
        if opcion == 1:
            puertos = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        elif opcion == 2:
            rango_puertos = simpledialog.askstring("Rango de puertos", "Introduce el rango de puertos a escanear (ej. 20-80):")
            if rango_puertos:
                rango_puertos = rango_puertos.split("-")
                puertos = range(int(rango_puertos[0]), int(rango_puertos[1]) + 1)
            else:
                messagebox.showerror("Error", "Rango de puertos no válido.")
                return
        else:
            messagebox.showerror("Error", "Opción no válida.")
            return
        self.result_text.insert(tk.END, f"\nEscaneando puertos en {ip}...\n")
        puertos_abiertos = escanear_puertos(ip, puertos)
        if puertos_abiertos:
            self.result_text.insert(tk.END, "Puertos abiertos encontrados:\n")
            for puerto in puertos_abiertos:
                servicio = puertos_servicios.get(puerto, "Desconocido")
                self.result_text.insert(tk.END, f"Puerto {puerto} ({servicio}) está abierto\n")
        else:
            self.result_text.insert(tk.END, "No se encontraron puertos abiertos.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()