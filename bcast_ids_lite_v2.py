#! /usr/bin/env python3

##############################################################################################
#                        BCAST_IDS: A NETWORK INTRUSION DETECTION SYSTEM
#                                      LITE VERSION
#
#                                      Dpto de Redes
#                               Gestion Tributaria Territorial
#                                           2020
##############################################################################################

import email
import smtplib
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
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from predict_iso_forest import predict_capture
from train_iso_forest import train_capture
from telegram_integration import send_message_telegram

"""Guarda JSON"""
def save_json(obj, name):
    with open(name, 'w') as fp:
        json.dump(obj, fp, sort_keys=True, indent=4)

"""Carga JSON"""
def load_json(name):
    with open(name, 'r') as f:
        return(json.load(f))

"""Guardamos cadena en un fichero de log"""
def save_text(name, salida_output, option):
    f = open(name, option)
    f.write(salida_output)
    f.close()

"""Leemos cadena de un fichero de log"""
def read_text(name):
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


""" Devuelve un diccionario con todos los valores del fichero config.txt """
def getValuesConfig():
    configFile_value = dict()
    filename = 'config.txt'
    with open(filename) as f_obj:
        lines = f_obj.readlines()
    for line in lines:
        if not line.startswith( '#' ) and not line.startswith( '\n' ):
            text = line.rstrip().split("=")[0]
            configFile_value[text]=line.rstrip().split("=")[1]
    return configFile_value

# Diccionario que almacena los valores del fichero config:
configFile_value = getValuesConfig()


""" Devuelve la MAC de la eth de la sonda """
def mac_eth_sonda():
    eth = configFile_value.get('IFACE2')
    mac_eth = os.popen("/sbin/ifconfig " + eth + " | grep -e ether | awk '{print $2}'").read().rstrip("\n").replace(':','')
    return mac_eth

# Almacenamos la MAC de la interfaz IFACE2 de la sonda en una variable
mac_sonda = mac_eth_sonda()

#...................................................................................

# CONSTANTES
AGING1 = int(configFile_value.get('UPDATE_TIME_JSON_HOUR'))
AGING2 = int(configFile_value.get('UPDATE_TIME_JSON_12HOURS'))
AGING3 = int(configFile_value.get('UPDATE_TIME_JSON_WEEK'))
AGING4 = int(configFile_value.get('UPDATE_TIME_JSON_MONTH'))
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
# Diccionario que obtiene las direcciones MACs que han realizado una solicitud ARP, IPv4 o IPv6 a la sonda
macAccess_protocol = dict()

"""Genera ficheros JSON: ipf, ipm, ti6, tip, tm"""
def generate_file(dir, datos_captura, ag):
    new_items = dict()
    global seconds
    aux = []
    exists = os.path.isfile(dir)
    if exists:
        datos_json = load_json(dir)

        # Recorremos JSON (cache)
        # Si una IP/MAC estaba en la cache y no se ha visto en 4 horas/12horas (ag) desde la ejecucion de este script, se borra de la cache
        if datos_json:
            for i in datos_json:
                res = seconds - datos_json[i]

                if res > ag:
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
                    datos_json[key_captura] = value_captura

            #Si una IP/MAC se ve activa y no existe, se crea de nuevo con la estampilla horaria actual
            else:
                # Comprobamos que los datos son menores que cuatro horas.
                if dir == './ipf.json':
                    if check_s(str(key_captura)) not in datos_json:
                        if seconds - value_captura < ag:
                            new_items[str(key_captura)]=value_captura
                else:
                    if seconds - value_captura < ag:
                        new_items[str(key_captura)]=value_captura

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
    sub_net = configFile_value.get('NET')
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
    proto = args[6]

    attributes[0] += 1

    #UNICAST, BROADCAST MULTICAST (tipo de direccionamiento)
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

        # ARP
        ## ARPpb + ARPan + ARPrq
        if arp_opcode == '0001' and mac_dst == 'ffffffffffff':
            attributes[4] += 1
        ## ARPgr
        elif arp_opcode == '0002' and mac_dst == 'ffffffffffff':
            attributes[4] += 1

        # Comprobamos si la MAC ha pregutado por la sonda usando el protocolo ARP
        if mac_dst == mac_sonda:
            #print(f"La MAC {mac_src} - {ip_src} ha preguntado por la sonda {mac_dst} - ARP - {eth_type}")
            if mac_src not in macAccess_protocol:
                proto.add('ARP')
                macAccess_protocol[mac_src]=proto
            else:
                macAccess_protocol[mac_src].add('ARP')

    #IPv4
    elif eth_type == '0800':
        protocol = int(binascii.hexlify(payload[23:24]), 16)
        dst_port = int(binascii.hexlify(payload[36:38]), 16)
        ip_src = ip_addr(payload[26:30])
        ip_dst = ip_addr(payload[30:34])

        #UDP=17
        if protocol == 17:
            attributes[7]+=1

            #SSDP
            if dst_port == 1900 and ip_dst == '239.255.255.250':
                attributes[13]+=1

        # TCP=6
        elif protocol == 6: attributes[8]+=1

        # ICMP=1
        elif protocol == 1: attributes[6]+=1

        # IP_RESTO
        else: attributes[9]+=1

        # Comprobamos si la MAC ha preguntado por la sonda usando el protocolo IPv4
        if mac_dst == mac_sonda:
            #print(f"La MAC {mac_src} - {ip_src} ha preguntado por la sonda {mac_dst} - IPv4 - {eth_type}")
            if mac_src not in macAccess_protocol:
                proto.add('IPv4')
                macAccess_protocol[mac_src]=proto
            else:
                macAccess_protocol[mac_src].add('IPv4')

    # IPv6
    elif eth_type == '86dd':
        # Contabilizamos paquetes IPv6
        attributes[10]+=1
        # Contabilizamos paquetes ICMPv6 (icmpv6_opcode == 00):
        icmpv6_opcode = binascii.hexlify(payload[55:56]).decode()
        if icmpv6_opcode == '00':
            attributes[14]+=1

        # Comprobamos si la MAC ha preguntado por la sonda usando el protocolo IPv6
        if mac_dst == mac_sonda:
            #print(f"La MAC {mac_src} - {ip_src} ha preguntado por la sonda {mac_dst} - IPv6 - {eth_type}")
            if mac_src not in macAccess_protocol:
                proto.add('IPv6')
                macAccess_protocol[mac_src]=proto
            else:
                macAccess_protocol[mac_src].add('IPv6')

    # RESTO
    else:
        attributes[11]+=1
        # Comprobamos si la MAC ha preguntado por la sonda usando otro protocolo
        if mac_dst == mac_sonda:
            #print(f"La MAC {mac_src} ha preguntado por la sonda {mac_dst} - {eth_type}")
            if mac_src not in macAccess_protocol:
                proto.add(eth_type)
                macAccess_protocol[mac_src]=proto
            else:
                macAccess_proto[mac_src].add(eth_type)


"""Lee el PCAP y contabiliza el numero de paquetes para generar el DATATSET:
Formato: {mac : 'MACs, UCAST, MCAST, BCAST, ARPrq, ARPpb, ARPan, ARPgr, LIPF, IP_ICMP, IP_UDP, IP_TCP, IP_RESTO, IP6, RESTO, ARP_noIP, SSDP, ICMPv6'} """
def mac_lines(pcap):
    # Obtenemos las direcciones MACs del fichero config con el formato apropiado
    excluye_macs = configFile_value.get('EXCLUDE_MACS').replace(':','').lower().split(',')

    num_attributes = 15
    attributes = [0] * num_attributes # Inicializamos la lista de valores de cada MAC a 0
    proto = set()

    for ts, payload in pcap:
        mac_src = binascii.hexlify(payload[6:12]).decode()
        mac_dst = binascii.hexlify(payload[0:6]).decode()
        eth_type = binascii.hexlify(payload[12:14]).decode()

        # Contabilizamos la cantidad de paquetes para cada direccion MAC
        if mac_src in mac_line:
            attributes = mac_line[mac_src]
            count_packets(ts,payload,attributes,mac_src,mac_dst,eth_type,proto)
        else:
            if mac_src not in excluye_macs and mac_src in ipm_subred:
                attributes = [0] * num_attributes
                mac_line[mac_src] = attributes
                count_packets(ts,payload,attributes,mac_src,mac_dst,eth_type,proto)

    # IPF. Contabiliza el num de asociaciones IP (MACs que han preguntado por una direccion IP que existe)
    if ipf:
        for line_ipf in ipf:
            ip_src_ipf = line_ipf.split("_")[0]
            ip_dst_ipf = line_ipf.split("_")[1]
            for mac_s, ip_s in ipm_subred.items():
                uniq_ipf_dst = set()
                if ip_src_ipf == ip_s:
                    #print(mac_s, ip_dst_ipf)
                    if mac_s in mac_line:
                        #print(mac_s, ip_dst_ipf)
                        if mac_s not in mac_ipf:
                            uniq_ipf_dst.add(ip_dst_ipf)
                            mac_ipf[mac_s]=uniq_ipf_dst
                        else:
                            mac_ipf[mac_s].add(ip_dst_ipf)
                        l = mac_line[mac_s]
                        l[5] += 1

    # ARP_nIP. Contabilizamos la cantidad de direcciones IPs que una MAC ha preguntado y que no existen en el fich ips-week.json
    if mac_nip:
        for mac, values_nip in mac_nip.items():
            if mac in mac_line:
                l = mac_line[mac]
                l[12] = len(values_nip)

    # Imprimimos las lineas para generar el DATASET
    if configFile_value.get('GENERATE_DATASET') == 'yes':
        print_mac_line()


"""Generamos las lineas del dataset con formato. Ordenamos de mas actividad a menor actividad."""
def print_mac_line():
    for key, value in sorted(mac_line.items(), key=lambda item: item[1][0], reverse=True):
        print(key, end=";")
        print(';'.join(map(str,value)))


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


""" Prediccion de la actividad de las direcciones MAC del dataset """
def run_IA():
    AI_applied = False
    # Si se encuentra un modelo entrenado se realiza la prediccion con el algoritmo Isolation Forest; o bien se analiza si una MAC ha preguntado por la MAC de la sonda
    if os.path.isfile('./predict_iso_forest.py') and os.path.isfile('./model_iso_forest.bin'):
        macs_atacando = []

        # Agrupacion y preparacion de los datos
        to_dataFrame = list()
        for key, value in sorted(mac_line.items(), key=lambda item: item[1][0], reverse=True):
            aux = list()
            aux.append(key)
            aux.extend(value)
            to_dataFrame.append(aux)

        # Tomamos la decision si aplicamos IA o se ha preguntado por la MAC origen de la sonda. Si la lista de macAccess_protocol esta vacia querra decir que no se ha preguntado por la sonda. Aplicamos IA.
        if not macAccess_protocol:
            # ISOLATION FOREST. Obtiene las direcciones MAC anomalas de la captura de 10 segundos en curso
            macs_atacando = predict_capture(to_dataFrame)
            AI_applied = True
        else:
            macs_atacando= list(macAccess_protocol.keys())

        # Si el algoritmo detecta alguna MAC que ha cometido alguna anomalia, el programa genera las siguientes alertas de seguridad:
        if macs_atacando:

            # Se guarda la captura en un PCAP en el directorio forensic/[direccion_MAC]
            save_cap(macs_atacando)

            # Se envia correo electronico
            if configFile_value.get('SEND_EMAIL') == 'yes':
                send_email_attack(macs_atacando)

            # Se envia alerta por Telegram
            if configFile_value.get('TELEGRAM_INTEGRATION')=='yes':
                alerta_telegram(macs_atacando)

            # Se registra en el fichero de log macs_abnormal_act.log las MACs que han cometido alguna anomalia y su actividad:
            for mac_atacando in macs_atacando:
                save_text("macs_abnormal_act.log", f"{dia} {hora} - MAC: {mac_atacando} - AI applied: {AI_applied} - Activity: {';'.join(map(str,mac_line[mac_atacando]))}\n", "a")
    else:
        if configFile_value.get('AUTOMATED_TRAINING')=='yes':
            if os.path.isfile('./time.tmp'):
                seconds_file = read_text('./time.tmp')
                if seconds - int(seconds_file) >= int(configFile_value.get('TIME_AUTOMATED_TRAINING')):
                    # Actualizamos el fichero time.tmp
                    save_text('./time.tmp', str(seconds), "w")

                    # Pasamos por parametro al algoritmo el nombre de fichero de texto y la contamination
                    name_dataset = configFile_value.get('FILENAME')
                    contamination = configFile_value.get('CONTAMINATION')

                    # Devuelve una cadena de si se ha podido realizar el entrenamiento correctamente
                    if configFile_value.get('GENERATE_OUTLIERS') == 'yes':
                        result_train = train_capture(f"./{name_dataset}.csv",contamination)
                    else:
                        result_train = train_capture(f"./{name_dataset}.csv",contamination, False)

                    save_text("messages_training.log", result_train, "a")
            else:
                save_text('./time.tmp', str(seconds), "w")


def alerta_telegram(macs_atacando):
    #header = "MAC;MACs;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;RESTO;ARP_noIP;SSDP;ICMPv6"
    # Obtenemos el chat_id:
    header = "MAC;MACs;UCAST;MCAST;BCAST;ARP;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;RESTO;ARP_noIP;SSDP;ICMPv6"
    chats_id = configFile_value.get('CHAT_ID').split(",")

    AI_applied = False
    # Damos formato al mensaje para enviarlo por Telegram al chat_id especificado en el config
    for chat_id in chats_id:
        activity_mac = ""
        activity_mac_log = ""
        message_to_telegram = ""
        cad = ""
        for mac_atacando in macs_atacando:
            activity_mac = mac_atacando+ ";" + ';'.join(map(str,mac_line[mac_atacando]))
            activity_mac_log += activity_mac + " "
            values = activity_mac.split(";")
            count= 0
            for i in header.split(";"):
                if count+1 == len(header.split(";")):
                    cad += f"{i}:{values[count]}\n\n"
                else:
                    cad += f"{i}:{values[count]}; "
                count +=1

        if not macAccess_protocol:
            AI_applied = True
            if  int(len(macs_atacando))==1:
                message_to_telegram = f"Abnormal MAC detected by AI. The activity was: \n\n{cad}"
            else:
                message_to_telegram = f"Abnormal MACs detected by AI. The activity was: \n\n{cad.rstrip()}"
        else:
            message_to_telegram = "Abnormal activity detected!\n\n"
            for mac_atacando in macs_atacando:
                message_to_telegram += f"Source MAC address {''.join(map(str, mac_atacando))} has generated {'/'.join(map(str,macAccess_protocol[''.join(map(str, mac_atacando))]))} packets towards BCAST_IDS MAC address destination ({mac_sonda})\n\n"
            message_to_telegram += f"The activity was: \n{cad}"

        # Enviamos la alerta por Telegram al chat_id o los chat_ids indicados en el fichero config.txt
        results_telegram = send_message_telegram(message_to_telegram, chat_id)

        # Almacenamos el resultado en un fichero de log
        if results_telegram[0]:
            save_text("telegram_messages.log", f"{dia} {hora} - OK: Telegram message sent to CHAT_ID {chat_id} - AI applied: {AI_applied} - {activity_mac_log}\n", "a")
        else:
            save_text("telegram_messages.log", f"{dia} {hora} - ERROR {results_telegram[1]} - Telegram message was not sent to CHAT_ID {chat_id} - AI applied: {AI_applied} - {activity_mac_log}\n", "a")


"""Envio de un correo electronico debido a que se ha detectado que una MAC ha producido un ataque."""
def send_email_attack(macs_atacando):
    global dia, hora
    receivers_email = configFile_value.get('RECEIVERS_EMAIL').split(",")

    AI_applied = False
    # Inicializamos el texto a mostrar por correo
    body_protocols=""
    dir_IP_MAC =""
    txt_ARP_nIP=""
    txt_IPF =""
    body =""

    # Cabecera del mensaje
    if len(macs_atacando) == 1:
        subject = "ALERT! MAC with unusual activity"
    else:
        subject = "ALERTA! MACs with unusual activity"

    #DETALLES de la MAC anomala en el cuerpo del mensaje:
    ## Direccion IP de la MAC
    ## Actividad de la MAC
    ## Direcciones IP que ha preguntado y NO existen (valores de ARP_nIP)
    ## Direcciones IP que una MAC ha preguntado y SI existen (valores de IPF)
    #registro_mac = "MAC;NUM_MAC;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP;SSDP;ICMPv6\n"
    registro_mac = "MAC;NUM_MAC;UCAST;MCAST;BCAST;ARP;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP;SSDP;ICMPv6\n"
    for mac_atacando in macs_atacando:
        if len(macs_atacando) == 1:
            if mac_atacando in macAccess_protocol:
                body =f"BCAST_IDS has detected that source MAC address {str(mac_atacando)} has generated {'/'.join(map(str,macAccess_protocol[''.join(map(str, mac_atacando))]))} packets towards the BCAST_IDS MAC address destination ({mac_sonda}) on {dia} at {hora}. See attached network capture (.cap file)."
            else:
                AI_applied = True
                body = f"BCAST_IDS has detected that MAC {str(mac_atacando)} had a suspicious behavior, using a Machine Learning algorithm, on {dia} at {hora}. See attached network capture (.cap file)."
        else:
            if mac_atacando in macAccess_protocol:
                body =f"BCAST_IDS has detected that MAC Source MAC address {str(mac_atacando)} has generated the following protocols towards the BCAST_IDS MAC address destination ({mac_sonda}) on {dia} at {hora}. See attached network capture (.cap file)."
                body_protocols += f"\n{mac_atacando}: {', '.join(map(str,macAccess_protocol[mac_atacando]))}"
            else:
                AI_applied = True
                body = f"BCAST_IDS has detected that MACs {', '.join(map(str,macs_atacando))} had a suspicious behavior, using a Machine Learning algorithm, on {dia} at {hora}. See attached network capture (.cap file)."
        registro_mac += mac_atacando + ";"
        registro_mac += ';'.join(map(str,mac_line[mac_atacando])) +"\n"
        if mac_atacando in ipm_subred:
            txt_dir_IP_MAC = "\nIP address:"
            dir_IP_MAC += f"\n{mac_atacando} - {ipm_subred[mac_atacando]}"
        if mac_atacando in mac_nip:
            txt_ARP_nIP += f"\nARP_noIP. IP addresses that MAC {mac_atacando} asked and DO NOT exist (ARP request): \n"
            txt_ARP_nIP += '; '.join(map(str,mac_nip[mac_atacando])) +"\n"
        if mac_atacando in mac_ipf:
            txt_IPF += f"\nIPF. IP addresses that MAC {mac_atacando} asked and EXIST (ARP request): \n"
            txt_IPF += '; '.join(map(str,mac_ipf[mac_atacando])) +"\n"

    # Completamos el cuerpo del mensaje
    body += body_protocols
    body += "\n\nDETAILS"
    body += txt_dir_IP_MAC
    body += dir_IP_MAC
    body += "\n\nActivity: \n"
    body += registro_mac
    body += txt_ARP_nIP
    body += txt_IPF

    # Enviamos el mensaje con el fichero pcap adjunto
    send_email(subject,body,receivers_email,True,macs_atacando,AI_applied)

""" Funcion que permite enviar un correo electronico cuando se incia el programa """
def send_email_ok():
    receivers_email = configFile_value.get('RECEIVERS_EMAIL').split(",")
    subject = "Email from BCAST_IDS sended correctly!"
    body = "Congrats! This email means that you have configured sending emails successfully. BCAST_IDS will let you know when network anomaly is detected."
    send_email(subject,body,receivers_email,False,None,AI_applied)

"""Envio de correos electronicos con el Asunto y Cuerpo del mensaje deseado"""
def send_email(*args):
    subject = args[0]
    body = args[1]
    attachment_pcap = args[3]
    macs_atacando = args[4]
    AI_applied = args[5]
    sender_email = configFile_value.get('SENDER_EMAIL')
    sender_password = configFile_value.get('SENDER_PASSWORD')
    receivers_email = args[2]

    mail_server = configFile_value.get('MAIL_SERVER')
    port_mail_server = int(configFile_value.get('PORT_MAIL_SERVER'))

    if attachment_pcap:
        filename = str(sys.argv[1])

        # Open PDF file in binary mode
        with open(filename, "rb") as attachment:
            # Add file as application/octet-stream
            # Email client can usually download this automatically as attachment
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        encoders.encode_base64(part)

        # Add header as key/value pair to attachment part
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {filename}",
        )

    ## Log in to server using secure context and send email
    try:
        for receiver_email in receivers_email:
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = receiver_email
            message["Subject"] = subject

            if attachment_pcap:
                message.attach(part)

            # Add body to email
            message.attach(MIMEText(body, "plain"))

            text = message.as_string()
            with smtplib.SMTP(mail_server, port_mail_server) as server:
                if sender_password:
                    server.starttls() #enable security
                    server.login(sender_email, sender_password) #login with mail_id and password
                server.sendmail(sender_email, receiver_email, text)
                server.quit()

            # Registramos en un fichero de log si se ha enviado el mensaje
            if macs_atacando != None:
                save_text("email_messages.log", f"{dia} {hora} e-Mail sent to {', '.join(map(str,receivers_email))} - AI applied: {AI_applied} - MACs with abnormal activity: {', '.join(map(str,macs_atacando))} \n", "a")
            else:
                save_text("email_messages.log", f"{dia} {hora} first e-Mail sent to {', '.join(map(str,receivers_email))} \n", "a")

    except Exception as e:
        # Registramos en un fichero de log si NO se ha enviado el mensaje por correo electronico
        if macs_atacando != None:
            save_text("email_messages.log", f"{dia} {hora} ERROR! e-Mail was not sent to {', '.join(map(str,receivers_email))} - AI applied: {AI_applied} - MACs with abnormal activity: {', '.join(map(str,macs_atacando))} \n\t\t NOTES: {e}. \n", "a")
        else:
            save_text("email_messages.log", f"{dia} {hora} ERROR! first e-Mail was not sent to {', '.join(map(str,receivers_email))}. Check your mail server configuration. \n\t\t If you want to check again the intregation of sending emails with BCAST_IDS, delete the file 'email_messages.log' and see again the results. \n\t\t NOTES: {e}. \n", "a")

if __name__ == '__main__':
    try:
        # Si no se encuentra el fichero de log email_messages.log, se realiza un primer intento de envio de correo electronico para comprobar si se ha configurado correctamente el servidor de correo.
        # if not os.path.isfile('email_messages.log') and configFile_value.get('SEND_EMAIL') == 'yes':
        #    send_email_ok()

        # Generamos los diccionarios de tm, tip, externos, ti6 e ipm
        f = open(sys.argv[1],'rb')
        pcap = dpkt.pcap.Reader(f)
        active_caches(pcap)
        f.close()

        # Generamos los ficheros JSON necesarios
        if tip:
            generate_file('./tips-week.json', tip, AGING3)
            generate_file('./tip.json', tip, AGING1)
        if tm:
            generate_file('./tm.json', tm, AGING1)
        if externos:
            generate_file('./externos.json', externos, AGING1)
        if ti6:
            generate_file('./ti6.json', ti6, AGING1)
        if ipm:
            generate_file('./ipm.json', ipm, AGING2)

        if os.path.isfile('./tips-week.json'):
            # Generamos diccionario de ipf
            f = open(sys.argv[1],'rb')
            pcap = dpkt.pcap.Reader(f)
            ipf_nipf(pcap)
            f.close()

        # Generamos fichero de asociacion de IPF:
        if ipf:
            generate_file('./ipf.json', ipf, AGING1)

        # Contabiliza el numero de paquetes de la captura por MAC:
        fa = open(sys.argv[1],'rb')
        pcapa = dpkt.pcap.Reader(fa)
        mac_lines(pcapa)
        fa.close()

        # Generamos fichero de MACs censadas en 1 mes
        if tm:
            generate_file('./tm-month.json', tm, AGING4)

        run_IA()

    except FileNotFoundError:
        print(f"ERROR! File {sys.argv[1]} not found. Insert an existing network capture (.cap) as a first argument.")
    except Exception as e:
        print(e)
