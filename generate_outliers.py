#!/usr/bin/env python3

##############################################################################################
#                        BCAST_IDS: A NETWORK INTRUSION DETECTION SYSTEM
#                               SCRIPT TO GENERATE OUTLIERS
#
#                                      Dpto de Redes
#                               Gestion Tributaria Territorial
#                                           2020
##############################################################################################

from numpy.random import seed
from numpy.random import randint
import numpy as np
import pandas as pd
import argparse
import sys
import os

# Diccionario mac_maxAct
mac_maxAct = dict()
#name_columns = ['MAC','NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']
name_columns = ['MAC','NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARP','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

""" We create the dataframe from a .csv file """
def generaDataFrame(dataset):
    try:
        # Convertimos el dataset en un DataFrame:
        dataFrame=pd.read_csv(dataset,sep=';',names=name_columns)
        dataFrame= dataFrame.fillna(0)
        to_model_columns=dataFrame.columns[1:19]
        dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)
        return dataFrame
    except FileNotFoundError:
        print(f"No se ha encontrado el Dataset {dataset}")
        exit(0)


""" Maximum values of each feature in th dataset"""
def ActMaxMacs(dataFrame, verbose=False):
    global mac_maxAct
    dfMaxMac = pd.DataFrame()
    uniq_macs = pd.DataFrame()
    mac_maxAct = dict()
    uniq_macs = dataFrame.MAC.unique()
    # Maximos valores de cada columna:
    if not dataFrame.empty:
        for mac in uniq_macs:
            dfMaxMac = dataFrame.loc[dataFrame['MAC'] == mac]
            dfMaxMac = dfMaxMac.drop(['MAC'], axis=1)
            dfMaxMac = dfMaxMac.max(axis=0)
            mac_maxAct[mac] = list(dfMaxMac)

        if verbose == True:
            print("Maximum values of each feature in the dataset")
            imprimeActMacs(mac_maxAct)


""" Chage the value of each feature by a percentaje """
def tunea_datos(dir_mac, porcentaje):
    global mac_maxAct
    if mac_maxAct:
        if dir_mac in mac_maxAct:
            new_values = []
            for value in mac_maxAct[dir_mac]:
                incremento = value * float(porcentaje)
                value = float(value) + incremento
                new_values.append(round(value))
            mac_maxAct[dir_mac] = new_values
            dict_aux = dict()
            dict_aux[dir_mac]=mac_maxAct[dir_mac]
            imprimeActMacs(dict_aux)

        elif dir_mac == "todos" or dir_mac == "todas" or dir_mac is None:
            for key, values in mac_maxAct.items():
                new_values = []
                for value in values:
                    incremento = value * float(porcentaje)
                    value = float(value) + incremento
                    new_values.append(round(value))
                mac_maxAct[key] = new_values
            imprimeActMacs(mac_maxAct)

        else:
            print("MAC address dos not appear in the dataset")


""" Print formatter """
def imprimeActMacs(param):
    for key, value in sorted(param.items(), key=lambda item: item[1][0], reverse=True):
        print(key, end=";")
        print(';'.join(map(str,value)))


# TYPICAL NETWORK SCANNING ATTACK
def generateOutliers(num):
    lista_actividad = []
    percentaje = 0.020 # Variacion
    # PORT SCANNING:
    for i in range(num):
        l = [0] * 15
        l[0] = randint(180, 800)
        l[1] = 0
        aux = 0
        aux = randint(0, 50)
        if aux <= 25:
            l[3] = randint(int(l[0] - percentaje * l[0]), l[0])
            l[2] = l[0] - l[3]
            l[4] = l[3]
        else:
            l[2] = 0
            l[3] = l[0]
            l[4] = l[0]
        temp = randint(0, 10)
        if temp <= 1:
            l[5] = randint(20, 80)
        else:
            l[5] = randint(0, 8)
        l[6] = randint(0, 1)
        l[7] = randint(0, 20)
        l[9] = randint(0, 5)
        l[10] = randint(0, 8)
        l[11] = randint(0, 2)
        l[12] = randint(170, 254) - l[5]
        ssdp = randint(0, 8)
        if ssdp <= l[7]:
            l[13]= ssdp
        else:
            l[13] = 0
        icmpv6 = randint(0, 3)
        if icmpv6 <= l[13]:
            l[14] = icmpv6
        else:
            l[14] = 0
        l = [f"auto_outlier{i}"] + l
        lista_actividad.append(l)
    return lista_actividad


""" Prediction of the activity of a set of MAC addresses. Returns a list of abnormal MACs in the current capture """
def outliers_to_dataframe(num):
    global name_columns
    dataset = generateOutliers(num)
    dataFrame = None

    try:
        # Read the captured data
        dataFrame = pd.DataFrame(dataset,columns=name_columns)
        # Prepare the data
        to_model_columns=dataFrame.columns[1:19]
        dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)

    except Exception as e:
        print(e)

    finally:
        return dataFrame

if __name__ == '__main__':
    text_help= "Script to make manual outliers from the dataset and print them in your screen."
    text_help += "\n\t./generate_outliers.py -n [num] -> Print a number of typical network scanning attack data patterns"
    text_help += "\n\t./generate_outliers.py -d [dataset.csv] -> Obtain the highest value of each feature of the dataset specified by parameter"
    text_help += "\n\t./generate_outliers.py -d [dataset.csv] -p [percentaje] -> Increase all the values of the MAC addresses features bear in mid the percntaje (i.e: 0.x)"
    text_help += "\n\t./generate_outliers.py -d [dataset.csv] -m [mac] -p [percentaje] -> Increase the value of the MAC address' features bear in mind the percentaje (i.e: 0.x)\n"

    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-n", "--scanning_network_attack", nargs=1, help="Print cyberattack data patterns (network scanning, SSDP attacks etc)")
    ap.add_argument("-m", "--MAC", required=False, help="MAC address")
    ap.add_argument("-p", "--percentaje", required=False, help="Modifies the data using a porcentual increment")
    ap.add_argument("-d", "--Dataset", required=False, help="Dataset name")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.scanning_network_attack:
        outliers = generateOutliers(int(args.scanning_network_attack[0]))
        for i in outliers:
            print(';'.join([str(elem) for elem in i]))

    if args.Dataset:
        dataset = vars(ap.parse_args())["Dataset"]
        dataFrame = generaDataFrame(dataset)
        if len(sys.argv) - 1 < 3:
            ActMaxMacs(dataFrame, True)
        else:
            ActMaxMacs(dataFrame)
        if args.percentaje:
            dir_mac = vars(ap.parse_args())["MAC"]
            porcentaje = vars(ap.parse_args())["percentaje"]
            tunea_datos(dir_mac, porcentaje)
