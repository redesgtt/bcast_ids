#!/usr/bin/python3.6

##############################################################################################
#                        BCAST_IDS: A NETWORK INTRUSION DETECTION SYSTEM
#                                      LITE VERSION
#
#                                      Dpto de Redes
#                               Gestion Tributaria Territorial
#                                           2020
##############################################################################################

import binascii
import dpkt
import sys
import csv
import json
import os
import time
import pickle
import json
import argparse
import sys
import psutil
from datetime import datetime
from itertools import islice

"""Guarda JSON"""
def save_json(obj, name):
    with open(name, 'w') as fp:
        json.dump(obj, fp, sort_keys=True, indent=4)

"""Carga JSON"""
def load_json(name):
    with open(name, 'r') as f:
        return(json.load(f))

"""Guarda resultado del algoritmo de IA en un fichero de txt"""
def save_txt(name, salida_output):
    f = open(name, "w")
    f.write(salida_output)
    f.close()

"""Lee el resultado del algoritmo de IA del fichero txt"""
def read_txt(name):
    f = open(name)
    return f.read()

"""Obtiene la direccion ETH de fich PCAP"""
def eth_addr (a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

"""Obtiene la direccion ETH byte de fichero PCAP"""
def eth_byte (b) :
    if len(b) == 2:
        e = "%.2x%.2x" % (ord(b[0]), ord(b[1]))
        return e
    else:
        return "0000"

"""Obtiene la direccion IP de fichero PCAP"""
def ip_addr (c) :
    #d = "%d.%d.%d.%d" % (ord(c[0]) , ord(c[1]) , ord(c[2]), ord(c[3])) # Python < 3
    d = "%d.%d.%d.%d" % (c[0],c[1],c[2],c[3])
    return d


""" Lee el fichero config.txt y obtiene los valores de NET, BANANA y EXCLUYE_MACs """
def getValuesConfig(text):
    encontrado = False
    values = list()
    filename = 'config.txt'
    with open(filename) as f_obj:
        lines = f_obj.readlines()

    for line in lines:
        if text in line and not encontrado:
            encontrado = True
            if text == "NET":
                values.append(line.rstrip().split("=")[1][1:-1])
            elif text == "EXCLUDE_MACS":
                values = line.rstrip().split("=")[1][1:-2].split(";")

    # No contiene nada. Generamos lista vacia
    if '' in values:
        values = list()

    return values

#...................................................................................

# CONSTANTES
AGING1=1800 #1h
AGING2=43200 #12h
AGING3=604800 #1 semana
AGING4=2592000 #30 dias

seconds = int(time.time())
dia = datetime.today().strftime('%d/%m/%Y')
hora = datetime.today().strftime('%H:%M')

# DICCIONARIOS
# ---- MACs activas ----
tm = dict()
# ---- IPS activas ----
tip = dict()
# ---- IPv6 activas ----
ti6 = dict()
# ---- IPF ----
ipf = dict()
# ---- IP_MAC ----
ipm = dict()
# ---- Asociacion IP-MAC en de la subred (NET)----
ipm_subred = dict()
# --- IPS que no estan en la subred --- #
externos = dict()
#Diccionario de las MACs que se han visto en la captura en curso:
mac_line = dict()
# Diccionario de las MACs que han preguntado por direcciones IP que no existen (peticiones ARP)
mac_nip = dict()
# Diccionario de las MACs que han preguntado por direcciones IP que si que existen (peticiones ARP)
mac_ipf = dict()

ts = 0

"""Genera ficheros JSON: ipf, ipm, ti6, tip, tm"""
def generate_file(dir, datos_captura, ag):
    new_items = dict()
    global seconds
    # print(datos_captura)
    aux = []
    exists = os.path.isfile(dir)
    if exists:
        datos_json = load_json(dir)

        # Recorremos JSON (cache)
        # Si una IP/MAC estaba en la cache y no se ha visto en 4 horas/12horas (ag) desde la ejecucion de este script, se borra de la cache
        if datos_json:
            for i in datos_json:
                res = seconds - datos_json[i]
                #print(datos_json[i])

                if res > ag:
                    #print(res)
                    aux.append(i)

            # Si la lista no esta vacia, significa que hay elementos para borrar
            if aux:
                for i in aux:
                    #print("borrado", i)
                    del datos_json[i]
                save_json(datos_json, dir)

        # Recorremos Captura
        for key_captura, val_captura in datos_captura.items():
            value_captura = int(val_captura)
            if key_captura in datos_json:
                # Actualizacion de tiempos si direccion MAC se encuentra activa y se ha visto en menos de 4 horas
                if seconds - value_captura < ag:
                    #print("Coincide: " + key_captura +", ", end=".")
                    #print("Cambio de valor: " + str(value_captura))
                    datos_json[key_captura] = value_captura

            #Si una IP/MAC se ve activa y no existe, se crea de nuevo con la estampilla horaria actual
            else:
                # print("Entramos aqui. No se ha detectado flag")
                # Comprobamos que los datos son menores que cuatro horas.
                if dir == './ipf.json':
                    if check_s(str(key_captura)) not in datos_json:
                        if seconds - value_captura < ag:
                            new_items[str(key_captura)]=value_captura
                else:
                    if seconds - value_captura < ag:
                        new_items[str(key_captura)]=value_captura

        # print (new_items)
        # Si se han detectado IPs/MACs nuevas y activas:
        if new_items:
            # Datos JSON + NUEVOS DATOS
            if datos_json:
                #print("Datos JSON + NUEVOS DATOS")
                json_new_items = dict(list(new_items.items()) + list(datos_json.items()))
                save_json(json_new_items, dir)

            # Solo NUEVOS DATOS
            elif not datos_json:
                #print(new_items)
                save_json(new_items, dir)

        elif not new_items:
            save_json(datos_json, dir)

    # Si en el directorio no se encuentra ningun fichero, se ha de guardar los datos capturados en un JSON
    else:
        for key_captura, val_captura in datos_captura.items():
            if seconds - val_captura < ag:
                save_json(datos_captura, dir)
            else:
                save_json(dict(), dir)


"""Evita duplicidades en el IPF. Ej: 192.168.3.2_192.168.3.57 = 192.168.3.57_192.168.3.2"""
def check_s(s):
    return(s.split('_')[1] + "_" + s.split('_')[0])

"""Funcion requerida para generar los valores de las tablas caches tip, ti6, ipm, externos y tip-week"""
def active_caches(pcap):
    sub_net = ''.join(getValuesConfig("NET"))
    for ts, payload in pcap:
        ts = int(ts)
        mac_src = binascii.hexlify(payload[6:12]).decode()
        mac_dst = binascii.hexlify(payload[0:6]).decode()
        eth_type = binascii.hexlify(payload[12:14]).decode()
        # Direcciones MAC sin duplicados
        if mac_src not in tm:
            tm[str(mac_src)] = int(ts)

        #ARP
        if eth_type == '0806':
           arp_opcode = binascii.hexlify(payload[20:22]).decode()
           ip_src = ip_addr(payload[28:32])
           ip_dst = ip_addr(payload[38:42])
           if arp_opcode == '0001' and mac_dst == 'ffffffffffff':
               if ip_src == "0.0.0.0": # ARPpb
                   pass
               elif ip_src == ip_dst:  # ARPan
                   pass
               else:
                   # Direcciones IP que pertencen a la LAN que estamos sniffando
                   if ip_src.startswith(sub_net):
                       if ip_src not in tip:
                           tip[ip_src] = int(ts)
                           ipm_subred[mac_src] = ip_src
                   else:
                        if ip_src not in externos:
                            externos[ip_src] = int(ts)

                   # IPM: Censo MACOrigen_IP origen que han realizado peticiones arp
                   if ip_src not in ipm:
                       s = str(mac_src)+"_"+str(ip_src)
                       ipm[s] = int(ts)

        elif eth_type == '0800':
            #Campo protocolo de la cabecera IP:
            protocol = int(binascii.hexlify(payload[23:24]), 16)
            ip_src = ip_addr(payload[26:30])

            # Direcciones IP que pertencen a la LAN que estamos sniffando
            if ip_src.startswith(sub_net):
                if ip_src not in tip:
                    tip[ip_src] = int(ts)
                    ipm_subred[mac_src] = ip_src
            else:
                if ip_src not in externos:
                    externos[ip_src] = int(ts)
        #IPv6
        elif eth_type == '86dd':
            mac_src = binascii.hexlify(payload[6:12]).decode()
            if mac_src not in ti6:
                ti6[mac_src] = int(ts)


""" Generamos las tablas caches ipf (asociaciones IPs validas) y mac_nip (asociaciones IPs que no son validas)"""
def ipf_nipf(pcap):
    tips_week = load_json('./tips-week.json')
    for ts, payload in pcap:
        nip = set()
        mac_src = binascii.hexlify(payload[6:12]).decode()
        mac_dst = binascii.hexlify(payload[0:6]).decode()
        eth_type = binascii.hexlify(payload[12:14]).decode()
        if eth_type == '0806':
           arp_opcode = binascii.hexlify(payload[20:22]).decode()
           ip_src = ip_addr(payload[28:32])
           ip_dst = ip_addr(payload[38:42])
           if arp_opcode == '0001' and mac_dst == 'ffffffffffff':
               if ip_src == "0.0.0.0": # ARPpb
                   pass
               elif ip_src == ip_dst:  # ARPan
                   pass
               else:
                   # IPF: IPs origen que han preguntado por IPs destino
                   if ip_dst in tips_week:
                       cad = ip_src + "_" + ip_dst
                       if cad not in ipf and check_s(cad) not in ipf:
                           ipf[cad] = int(ts)

                   # MACs que han preguntado por peticiones IPs que no existen
                   if ip_dst not in tips_week:
                       if mac_src not in mac_nip:
                           nip.add(ip_dst)
                           mac_nip[mac_src]=nip
                       else:
                           mac_nip[mac_src].add(ip_dst)


""" Contabilizamos los paquetes generados por una direccion MAC especifica """
def count_packets(*args):
    ts = args[0]
    payload = args[1]
    attributes = args[2]
    mac_src = args[3]
    mac_dst = args[4]
    eth_type = args[5]

    # Total de veces que ha aparecido la MAC
    attributes[0] += 1

    #Tipo de direccionamiento: Unicast, Broadcast o Multicast
    ETH_MSB_IG = ord(payload[0:1])
    if  (ETH_MSB_IG & 1) == 0 :   # UCAST
        #print ("UCAST", mac_src,mac_dst,eth_type)
        attributes[1] += 1

    elif mac_dst == 'ffffffffffff':  # BCAST
        #print ("BCAST", mac_src,mac_dst,eth_type)
        attributes[3] += 1

    elif (ETH_MSB_IG & 1) == 1:  # MCAST
        #print ("MCAST", mac_src,mac_dst,eth_type)
        attributes[2] += 1
    #ARP
    if eth_type == '0806':
        arp_opcode = binascii.hexlify(payload[20:22]).decode()
        ip_src = ip_addr(payload[28:32])
        ip_dst = ip_addr(payload[38:42])
        if arp_opcode == '0001' and mac_dst == 'ffffffffffff':
            if ip_src == "0.0.0.0": # ARPpb
                #print (mac_src,mac_dst,eth_type,arp_opcode,ip_src,ip_dst)
                attributes[5] += 1
            elif ip_src == ip_dst:  # ARPan
                #print (mac_src,mac_dst,eth_type,arp_opcode,ip_src,ip_dst)
                attributes[6] += 1
            else:
                #print (mac_src,mac_dst,eth_type,arp_opcode,ip_src,ip_dst)
                attributes[4] += 1          # ARPrq
                #print(mac_src, ip_src)
        elif arp_opcode == '0002' and mac_dst == 'ffffffffffff':
            attributes[7] += 1          # ARPgr
        #IPv4
        elif eth_type == '0800':
            protocol = int(binascii.hexlify(payload[23:24]), 16)
            ip_src = ip_addr(payload[26:30])

            #UDP=17
            if protocol == 17: attributes[10]+=1

            # TCP=6
            elif protocol == 6: attributes[11]+=1

            # ICMP=1
            elif protocol == 1: attributes[9]+=1

            # IP_RESTO
            else: attributes[12]+=1

            #IPv6
        elif eth_type == '86dd': attributes[13]+=1

        #RESTO
        else: attributes[14]+=1


"""Lee el PCAP y contabiliza el numero de paquetes para generar el DATATSET:
Formato: {mac : 'MACs, UCAST, MCAST, BCAST, ARPrq, ARPpb, ARPan, ARPgr, LIPF, IP_ICMP, IP_UDP, IP_TCP, IP_RESTO, IP6, RESTO, ARP_noIP'} """
def mac_lines(pcap):
    excluye_macs = getValuesConfig("EXCLUYE_MACS")
    mac_ataque_dataset = ""
    attributes = [0] * 16 # Inicializamos la lista de valores de cada MAC a 0
    for ts, payload in pcap:
        mac_src = binascii.hexlify(payload[6:12]).decode()
        mac_dst = binascii.hexlify(payload[0:6]).decode()
        eth_type = binascii.hexlify(payload[12:14]).decode()

        # Contabilizamos la cantidad de paquetes para cada direccion MAC
        if mac_src in mac_line and mac_src not in excluye_macs:
            attributes = mac_line[mac_src]
            count_packets(ts,payload,attributes,mac_src,mac_dst,eth_type)
        else:
            if mac_src in ipm_subred and mac_src not in excluye_macs:
                attributes = [0] * 16
                mac_line[mac_src] = attributes
                count_packets(ts,payload,attributes,mac_src,mac_dst,eth_type)

    # IPF. Contabiliza el num de asociaciones IP (MACs que han preguntado por una direccion IP que existe)
    if ipf:
        for line_ipf in ipf:
            ip_src_ipf = line_ipf.split("_")[0]
            ip_dst_ipf = line_ipf.split("_")[1]
            for mac_s, ip_s in ipm_subred.items():
                #uniq_ipf_dst = set()
                if ip_src_ipf == ip_s:
                    #print(mac_s, ip_dst_ipf)
                    if mac_s in mac_line:
                        #print(mac_s, ip_dst_ipf)
                        #if mac_s not in mac_ipf:
                        #    uniq_ipf_dst.add(ip_dst_ipf)
                        #    mac_ipf[mac_s]=uniq_ipf_dst
                        #else:
                        #    mac_ipf[mac_s].add(ip_dst_ipf)
                        l = mac_line[mac_s]
                        l[8] += 1

    # ARP_nIP. Contabilizamos la cantidad de direcciones IPs que una MAC ha preguntado y que no existen en el fich ips-week.json
    if mac_nip:
        for mac, values_nip in mac_nip.items():
            if mac in mac_line:
                l = mac_line[mac]
                l[15] = len(values_nip)

    # Imprimimos las lineas para generar el DATASET
    print_mac_line()


"""Generamos las lineas del dataset con formato. Ordenamos de mas actividad a menor actividad."""
def print_mac_line():
    for key, value in sorted(mac_line.items(), key=lambda item: item[1][0], reverse=True):
        print(key, end=";")
        print(';'.join(map(str,value)))


"""Comprobamos si se ha detectado una MAC que no se encuentra censada en tm-month.json"""
def check_macs():
    MACS_nuevas = list()
    dir = './tm-month.json'
    macs_captura = list(mac_line.keys())
    exists = os.path.isfile(dir)
    if exists:
        datos_json = load_json(dir)
        for mac_captura in macs_captura:
            if mac_captura not in datos_json:
                print(f"ALERTA! Se ha detectado nueva MAC en la red ({mac_captura})")

"""Para obtener las primeras n MACs de mas actividad de la captura"""
def take(n, iterable):
    return dict(islice(iterable, n))


"""Guarda la captura en el directorio forensic"""
def save_cap(macs_atacando):
    d = datetime.today().strftime('%Y-%m-%d-%H:%M')
    path = "forensic/"

    # define the access rights
    access_rights = 0o777

    if not os.path.exists(path):
        os.mkdir(path, access_rights)
    for mac in macs_atacando:
        path_mac = path + mac + "/"
        if not os.path.exists(path_mac):
            os.mkdir(path_mac, access_rights)
        c = "cp " + str(sys.argv[1]) + " " + path_mac + str(d) +".cap"
        os.system(c)



"""Funcion que invoca al Random/Isolation Forest para realizar la prediccion si una MAC ha cometido un ataque.
   Se analizan las primeras 5 MACs que tienen una mayor actividad.
   Tambien se envian valores a Nagios para su representacion Grafica en Dashboards > Banana
   Si el algoritmo detecta un ataque; envia un correo electronico al dept. de redes y guarda la captura en directorio /forensic"""
def run_IA():
    if os.path.isfile('./predict_iso_forest.py') and os.path.isfile('./model_iso_forest.bin'):
        macs_atacando = []
        order_dict= dict()
        for key, value in sorted(mac_line.items(), key=lambda item: item[1][0], reverse=True):
            order_dict[key]=value

        n_items = take(5, order_dict.items())

        # Creamos la cadena de entrada para el script de prediccion(c): mac;MACs;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;LIPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;RESTO;ARP_noIP
        for key, value in n_items.items():
            a = key + ";"
            b =';'.join(map(str,value))
            c = a+b

            result_predict = os.system("./predict_iso_forest.py -s" + '"' + c + '"' + "> output_predict.txt") #ISOLATION FOREST

            si_output = read_txt("output_predict.txt")
            s_output = si_output[1:-2]

            # El algoritmo Isolation Forest tiene como salida -1 en caso de que haya un ataque
            if s_output == str(-1):
                macs_atacando.append(key)

        # Si hay ataque, mostramos las MACs que se encuentran atacando y realizamos una llamada a Nagios.
        if macs_atacando:
        
            #Guardamos captura de la MAC atacante
            save_cap(macs_atacando)

            # Realizamos un DROP de la MAC en el switch correspondiente:
            for mac_atacando in macs_atacando:
                print("f MAC {mac_atacando} atacando!")


if __name__ == '__main__':

    # Generamos los diccionarios de tm, tip, externos, ti6 e ipm
    f = open(sys.argv[1],'rb')
    pcap = dpkt.pcap.Reader(f)
    active_caches(pcap)
    f.close()

    # Generamos los ficheros JSON necesarios
    generate_file('./tips-week.json', tip, AGING3)
    generate_file('./tip.json', tip, AGING1)
    generate_file('./tm.json', tm, AGING1)
    generate_file('./externos.json', externos, AGING1)
    generate_file('./ti6.json', ti6, AGING1)
    generate_file('./ipm.json', ipm, AGING2)

    # Generamos diccionario de ipf
    f = open(sys.argv[1],'rb')
    pcap = dpkt.pcap.Reader(f)
    ipf_nipf(pcap)
    f.close()

    # Generamos fichero de asociacion de IPF:
    generate_file('./ipf.json', ipf, AGING1)

    # Contabiliza el numero de paquetes de la captura por MAC:
    fa = open(sys.argv[1],'rb')
    pcapa = dpkt.pcap.Reader(fa)
    mac_lines(pcapa)
    fa.close()

    # Comprueba si se ha detectado una direccion MAC que no esta en el JSON
    check_macs()

    # Generamos fichero de MACs censadas en 1 mes
    generate_file('./tm-month.json', tm, AGING4)

    # Aplicamos algoritmo IA
    run_IA()
