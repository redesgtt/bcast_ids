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
        dst_port = int(binascii.hexlify(payload[36:38]), 16)
        ip_src = ip_addr(payload[26:30])
        ip_dst = ip_addr(payload[30:34])

        #UDP=17
        if protocol == 17:
            attributes[10]+=1

            #SSDP
            if dst_port == 1900 and ip_dst == '239.255.255.250':
                attributes[16]+=1

        # TCP=6
        elif protocol == 6: attributes[11]+=1

        # ICMP=1
        elif protocol == 1: attributes[9]+=1

        # IP_RESTO
        else: attributes[12]+=1

    # IPv6
    elif eth_type == '86dd':
        #print("Trafico IPv6 detectado", mac_src)

        # Contabilizamos paquetes IPv6
        attributes[13]+=1

        # Contabilizamos paquetes ICMPv6 (icmpv6_opcode == 00):
        icmpv6_opcode = binascii.hexlify(payload[55:56]).decode()
        if icmpv6_opcode == '00':
            attributes[17]+=1
    # RESTO
    else: attributes[14]+=1


"""Lee el PCAP y contabiliza el numero de paquetes para generar el DATATSET:
Formato: {mac : 'MACs, UCAST, MCAST, BCAST, ARPrq, ARPpb, ARPan, ARPgr, LIPF, IP_ICMP, IP_UDP, IP_TCP, IP_RESTO, IP6, RESTO, ARP_noIP, SSDP, ICMPv6'} """
def mac_lines(pcap):
    excluye_macs = configFile_value.get('EXCLUDE_MACS').split(",")
    num_attributes = 18
    attributes = [0] * num_attributes # Inicializamos la lista de valores de cada MAC a 0
    #print(attributes)
    for ts, payload in pcap:
        mac_src = binascii.hexlify(payload[6:12]).decode()
        mac_dst = binascii.hexlify(payload[0:6]).decode()
        eth_type = binascii.hexlify(payload[12:14]).decode()

        # Contabilizamos la cantidad de paquetes para cada direccion MAC
        if mac_src in mac_line:
            attributes = mac_line[mac_src]
            count_packets(ts,payload,attributes,mac_src,mac_dst,eth_type)
        else:
            if mac_src not in excluye_macs and mac_src in ipm_subred:
                attributes = [0] * num_attributes
                mac_line[mac_src] = attributes
                count_packets(ts,payload,attributes,mac_src,mac_dst,eth_type)

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
                        l[8] += 1

    # ARP_nIP. Contabilizamos la cantidad de direcciones IPs que una MAC ha preguntado y que no existen en el fich ips-week.json
    if mac_nip:
        for mac, values_nip in mac_nip.items():
            if mac in mac_line:
                l = mac_line[mac]
                l[15] = len(values_nip)

    # Imprimimos las lineas para generar el DATASET
    if configFile_value.get('GENERATE_DATASET') == 'yes':
        print_mac_line()



"""Generamos las lineas del dataset con formato. Ordenamos de mas actividad a menor actividad."""
def print_mac_line():
    for key, value in sorted(mac_line.items(), key=lambda item: item[1][0], reverse=True):
        print(key, end=";")
        print(';'.join(map(str,value)))


"""Registramos la primera vez que se ha visualizado una direccion MAC y que no se encuentre censada en el fichero JSON"""
def check_macs():
    MACS_nuevas = list()
    dir = './tm-month.json'
    macs_captura = list(mac_line.keys())
    exists = os.path.isfile(dir)
    if exists:
        datos_json = load_json(dir)
        for mac_captura in macs_captura:
            if mac_captura not in datos_json:
                #f = open("new_macs_detected.log", "a")
                #f.write(f"{dia} {hora} - {mac_captura}\n")
                #f.close()
                save_text("new_macs_detected.log", f"{dia} {hora} - {mac_captura}\n", "a")


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
    # Si se encuentra un modelo entrenado, realice la prediccion
    if os.path.isfile('./predict_iso_forest.py') and os.path.isfile('./model_iso_forest.bin'):
        macs_atacando = []

        # Agrupacion de los datos
        to_dataFrame = list()
        for key, value in sorted(mac_line.items(), key=lambda item: item[1][0], reverse=True):
            aux = list()
            aux.append(key)
            aux.extend(value)
            to_dataFrame.append(aux)

        # ISOLATION FOREST. Obtiene las direcciones MAC anomalas:
        macs_atacando = predict_capture(to_dataFrame)
        #print(macs_atacando)

        # Si el algoritmo detecta alguna MAC que ha cometido alguna anomalia
        if macs_atacando:

            # Se guarda la captura en un PCAP en forensic/numero_MAC
            save_cap(macs_atacando)

            # Se envia correo electronico
            if configFile_value.get('SEND_EMAIL') == 'yes':
                send_email_attack(macs_atacando)

            # Se registra en un fichero de log
            for mac_atacando in macs_atacando:
                save_text("macs_abnormal_act.log", f"{dia} {hora} - {mac_atacando}\n", "a")
    else:
        if configFile_value.get('AUTOMATED_TRAINING')=='yes':
            if os.path.isfile('./time.tmp'):
                seconds_file = read_text('./time.tmp')
                if seconds - int(seconds_file) >= int(configFile_value.get('TIME_AUTOMATED_TRAINING')):
                    print(f"Han pasado mas de {seconds - int(seconds_file)} segundos. Entrenamos el algoritmo con los datos recogidos hasta ahora")

                    # Actualizamos el fichero time.tmp
                    save_text('./time.tmp', str(seconds), "w")

                    # Pasamos por parametro al algoritmo el nombre de fichero de texto y la contamination
                    name_dataset = configFile_value.get('FILENAME')
                    contamination = configFile_value.get('CONTAMINATION')

                    # Entrenamos el modelo con contamination 'auto' en caso contrario especificar como segundo parametro
                    print("Comenzamos entrenamiento...")
                    if train_capture(f"./{name_dataset}.csv",contamination):
                        # TODO: Escribir mensaje en un fichero de log
                        print("Finalizamos el entrenamiento y se guarda en un modelo")
                        # TODO: Guardar las MACs que el algoritmo ha detectado como anomalas
                    else:
                        # TODO: Escribir mensaje en un fichero de log
                        print("FALLO EN EL ENTRENAMIENTO")

                    #print(results_training)
                    #save_text('./results_training.tmp', str(results_training), "w")
            else:
                save_text('./time.tmp', str(seconds), "w")
                #print(f"Guardamos el fichero de time.tmp con el valor de {seconds}")


"""Envio de un correo electronico debido a que se ha detectado que una MAC ha producido un ataque."""
def send_email_attack(macs_atacando):
    global dia, hora
    receivers_email = configFile_value.get('RECEIVERS_EMAIL').split(",")

    # Inicializamos el texto a mostrar por correo
    mac_interfaz_switch = ""
    ubicacion_fisica = ""
    dir_IP_MAC =""
    txt_ARP_nIP=""
    txt_IPF =""
    body =""

    # Cabecera del mensaje
    if len(macs_atacando) == 1:
        subject = "ALERTA! MAC con actividad inusual"
    else:
        subject = "ALERTA! MACs con actividad inusual"

    #DETALLES de la MAC anomala en el cuerpo del mensaje:
    ## Direccion IP de la MAC
    ## Ubicacion fisica de la MAC
    ## Actividad de la MAC
    ## Direcciones IP que ha preguntado y NO existen (valores de ARP_nIP)
    ## Direcciones IP que una MAC ha preguntado y SI existen (valores de IPF)
    registro_mac = "MAC;NUM_MAC;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP\n"
    for mac_atacando in macs_atacando:
        if len(macs_atacando) == 1:
            body = f"BCAST_IDS ha detectado que la MAC {str(mac_atacando)} ha tenido un comportamiento sospechoso el dia {dia} a las {hora}. Se anexa captura de red para su analisis. \n\nDETALLES:"
        else:
            body = f"BCAST_IDS ha detectado que las MAC {', '.join(map(str,macs_atacando))} han tenido un comportamiento sospechoso el dia {dia} a las {hora}. Se anexa captura de red para su analisis. \n\nDETALLES:"
        registro_mac += mac_atacando + ";"
        registro_mac += ';'.join(map(str,mac_line[mac_atacando])) +"\n"
        if mac_atacando in ipm_subred:
            txt_dir_IP_MAC = "\nDireccion IP:"
            dir_IP_MAC += f"\n{mac_atacando} -> {ipm_subred[mac_atacando]}"
        if mac_atacando in mac_nip:
            txt_ARP_nIP += f"\nARP_noIP. Direcciones IP que ha preguntado la MAC {mac_atacando} y NO existen (peticiones ARP): \n"
            txt_ARP_nIP += '; '.join(map(str,mac_nip[mac_atacando])) +"\n"
        if mac_atacando in mac_ipf:
            txt_IPF += f"\nIPF. Direcciones IP que ha preguntado la MAC {mac_atacando} y SI existen (peticiones ARP): \n"
            txt_IPF += '; '.join(map(str,mac_ipf[mac_atacando])) +"\n"

    # Completamos el cuerpo del mensaje
    body += txt_dir_IP_MAC
    body += dir_IP_MAC
    body += "\n" + ubicacion_fisica
    body += mac_interfaz_switch
    body += "\n\nActividad registrada: \n"
    body += registro_mac
    body += txt_ARP_nIP
    body += txt_IPF

    # Enviamos el mensaje con el fichero pcap adjunto
    send_email(subject,body,receivers_email,True,macs_atacando)


"""Envio de correos electronicos con el Asunto y Cuerpo del mensaje deseado"""
def send_email(*args):
    subject = args[0]
    body = args[1]
    attachment_pcap = args[3]
    macs_atacando = args[4]

    sender_email = configFile_value.get('SENDER_EMAIL')
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
                server.sendmail(sender_email, receiver_email, text)
                # Registramos en un fichero de log si se ha enviado el mensaje
                save_text("email_messages.log", f"{dia} {hora} CORREO ELECTRONICO ENVIADO A {', '.join(map(str,receivers_email))} - MACs con act anomalas: {', '.join(map(str,macs_atacando))} \n", "a")

    except:
        # Registramos en un fichero de log si NO se ha eniado el mensaje por correo electronico
        save_text("email_messages.log", f"{dia} {hora} ERROR EN EL ENVIO DEL CORREO ELECTRONICO (revisa los valores de MAIL_SERVER, PORT_MAIL_SERVER, SENDER_EMAIL y RECEIVERS_EMAIL del fichero config.txt) - MACs con act anomalas: {', '.join(map(str,macs_atacando))} \n", "a")
        #f = open("email_messages.log", "a")
        #f.write(f"{dia} {hora} ERROR EN EL ENVIO DEL CORREO ELECTRONICO (revisa los valores de MAIL_SERVER, PORT_MAIL_SERVER, SENDER_EMAIL y RECEIVERS_EMAIL del fichero config.txt)  - MACs con act anomalas: {', '.join(map(str,macs_atacando))}\n")
        #f.close()


if __name__ == '__main__':
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

    # Comprueba si se ha detectado una direccion MAC que no esta en el JSON
    check_macs()

    # Generamos fichero de MACs censadas en 1 mes
    if tm:
        generate_file('./tm-month.json', tm, AGING4)

    # Aplicamos algoritmo IA
    run_IA()
