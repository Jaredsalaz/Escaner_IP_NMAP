from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from mac_vendor_lookup import MacLookup
import nmap
import pdfkit

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
    print(f"Escaneando la red en el rango: {rango_ip}")
    arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp
    resultado = srp(paquete, timeout=3, verbose=1)[0]
    dispositivos = [{'ip': recibido.psrc, 'mac': recibido.hwsrc} for enviado, recibido in resultado]
    print(f"Dispositivos encontrados: {dispositivos}")
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

def escanear_vulnerabilidades(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV --script=vuln')
    return nm[ip]

def detectar_sistema_operativo(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O', timeout=60)
    except nmap.PortScannerError as e:
        print(f"Error al detectar el sistema operativo: {e}")
        return {}
    except Exception as e:
        print(f"Error inesperado: {e}")
        return {}
    return nm[ip]

def generar_reporte_html(dispositivos, filename='reporte.html'):
    html_content = "<html><head><title>Reporte de Escaneo</title></head><body>"
    html_content += "<h1>Reporte de Escaneo de Red</h1>"
    html_content += "<table border='1'><tr><th>ID</th><th>IP</th><th>MAC</th><th>Fabricante</th><th>Sistema Operativo</th></tr>"
    for idx, dispositivo in enumerate(dispositivos):
        html_content += f"<tr><td>{idx+1}</td><td>{dispositivo['ip']}</td><td>{dispositivo['mac']}</td><td>{dispositivo['fabricante']}</td><td>{dispositivo.get('os', 'Desconocido')}</td></tr>"
    html_content += "</table></body></html>"
    with open(filename, 'w') as f:
        f.write(html_content)
    pdfkit.from_file(filename, filename.replace('.html', '.pdf'))

def main():
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
        print("Asegúrate de que nmap esté instalado y en el PATH del sistema.")
        return

    while True:
        try:
            rango_ip = input("Introduce el rango de IPs a escanear (ej. 192.168.1.0/24): ")

            dispositivos = escanear_red(rango_ip)
            mac_lookup = MacLookup()

            print("Dispositivos encontrados en la red:")
            print("ID  IP" + " "*18 + "MAC" + " "*18 + "Fabricante")
            for idx, dispositivo in enumerate(dispositivos):
                try:
                    fabricante = mac_lookup.lookup(dispositivo['mac'])
                except KeyError:
                    fabricante = "Desconocido"
                dispositivo['fabricante'] = fabricante
                os_info = detectar_sistema_operativo(dispositivo['ip'])
                dispositivo['os'] = os_info.get('osclass', [{}])[0].get('osfamily', 'Desconocido')
                print(f"{idx+1:2}  {dispositivo['ip']:16}    {dispositivo['mac']:17}    {fabricante}    {dispositivo['os']}")

            if not dispositivos:
                print("No se encontraron dispositivos en la red.")
                continue

            seleccion = int(input("\nSelecciona el ID de la IP que deseas escanear los puertos: ")) - 1
            ip_seleccionada = dispositivos[seleccion]['ip']

            print("\nOpciones de escaneo de puertos:")
            print("1. Escanear puertos más vulnerables (backdoors)")
            print("2. Escanear un rango específico de puertos")
            opcion = int(input("Selecciona una opción: "))

            if opcion == 1:
                puertos = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            elif opcion == 2:
                rango_puertos = input("Introduce el rango de puertos a escanear (ej. 20-80): ")
                rango_puertos = rango_puertos.split("-")
                puertos = range(int(rango_puertos[0]), int(rango_puertos[1]) + 1)
            else:
                print("Opción no válida.")
                continue

            print(f"\nEscaneando puertos en {ip_seleccionada}...")
            puertos_abiertos = escanear_puertos(ip_seleccionada, puertos)
            if puertos_abiertos:
                print("Puertos abiertos encontrados:")
                for puerto in puertos_abiertos:
                    servicio = puertos_servicios.get(puerto, "Desconocido")
                    print(f"Puerto {puerto} ({servicio}) está abierto")
            else:
                print("No se encontraron puertos abiertos.")

            print("\nEscaneando vulnerabilidades en la IP seleccionada...")
            vulnerabilidades = escanear_vulnerabilidades(ip_seleccionada)
            print("Vulnerabilidades encontradas:")
            for script in vulnerabilidades['hostscript']:
                print(f"{script['id']}: {script['output']}")

            generar_reporte = input("\n¿Deseas generar un reporte? (s/n): ").lower()
            if generar_reporte == 's':
                generar_reporte_html(dispositivos)
                print("Reporte generado exitosamente.")

            continuar = input("\n¿Deseas realizar otro escaneo? (s/n): ").lower()
            if continuar != 's':
                print("Saliendo del programa.")
                break

        except KeyboardInterrupt:
            print("\nInterrupción manual detectada. Saliendo del programa.")
            break
        except Exception as e:
            print(f"Error inesperado: {e}")
            break

if __name__ == "__main__":
    main()