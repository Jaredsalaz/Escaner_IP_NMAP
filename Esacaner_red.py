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
    # Crear una solicitud ARP
    arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp

    # Enviar el paquete y recibir las respuestas
    resultado = srp(paquete, timeout=3, verbose=0)[0]

    # Crear una lista de dispositivos encontrados
    dispositivos = []
    for enviado, recibido in resultado:
        dispositivos.append({'ip': recibido.psrc, 'mac': recibido.hwsrc})

    return dispositivos

def escanear_puertos(ip, puertos):
    puertos_abiertos = []
    for puerto in puertos:
        pkt = IP(dst=ip)/TCP(dport=puerto, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is not None and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            puertos_abiertos.append(puerto)
            sr1(IP(dst=ip)/TCP(dport=puerto, flags="R"), timeout=1, verbose=0)  # Enviar RST para cerrar la conexión
    return puertos_abiertos

def main():
    while True:
        # Rango de IPs a escanear (ajusta según tu red)
        rango_ip = "192.168.1.0/24"

        # Escanear la red
        dispositivos = escanear_red(rango_ip)

        # Inicializar el objeto MacLookup
        mac_lookup = MacLookup()

        # Imprimir los dispositivos encontrados
        print("Dispositivos encontrados en la red:")
        print("ID  IP" + " "*18 + "MAC" + " "*18 + "Fabricante")
        for idx, dispositivo in enumerate(dispositivos):
            try:
                fabricante = mac_lookup.lookup(dispositivo['mac'])
            except KeyError:
                fabricante = "Desconocido"
            print(f"{idx+1:2}  {dispositivo['ip']:16}    {dispositivo['mac']:17}    {fabricante}")

        # Permitir al usuario seleccionar una IP para escanear puertos
        seleccion = int(input("\nSelecciona el ID de la IP que deseas escanear los puertos: ")) - 1
        ip_seleccionada = dispositivos[seleccion]['ip']

        # Menú de opciones de escaneo de puertos
        print("\nOpciones de escaneo de puertos:")
        print("1. Escanear puertos más vulnerables (backdoors)")
        print("2. Escanear un rango específico de puertos")
        opcion = int(input("Selecciona una opción: "))

        if opcion == 1:
            # Puertos más vulnerables (backdoors)
            puertos = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        elif opcion == 2:
            # Solicitar al usuario que introduzca el rango de puertos a escanear
            rango_puertos = input("Introduce el rango de puertos a escanear (ej. 20-80): ")
            rango_puertos = rango_puertos.split("-")
            puertos = range(int(rango_puertos[0]), int(rango_puertos[1]) + 1)
        else:
            print("Opción no válida.")
            continue

        # Escanear los puertos en la IP seleccionada
        print(f"\nEscaneando puertos en {ip_seleccionada}...")
        puertos_abiertos = escanear_puertos(ip_seleccionada, puertos)
        if puertos_abiertos:
            print("Puertos abiertos encontrados:")
            for puerto in puertos_abiertos:
                servicio = puertos_servicios.get(puerto, "Desconocido")
                print(f"Puerto {puerto} ({servicio}) está abierto")
        else:
            print("No se encontraron puertos abiertos.")

        # Preguntar al usuario si desea realizar otro escaneo
        continuar = input("\n¿Deseas realizar otro escaneo? (s/n): ").lower()
        if continuar != 's':
            print("Saliendo del programa.")
            break

if __name__ == "__main__":
    main()