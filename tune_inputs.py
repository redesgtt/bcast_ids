#! /usr/bin/env python3

####################################################################################
#
#       Proposito y funcionalidades:
#
#         Tunear la actividad de una direccion MAC de manera proporcional, aplicando
#          un tanto por uno de variacion para generar Outliers.
#
#       Fecha:
#               (JGFC) 28/07/2020
#                       Finalizacion del script
#
####################################################################################

import numpy as np
import pandas as pd
import argparse
import sys
import os

# Diccionario mac_maxAct
mac_maxAct = dict()

""" Generamos un DataFrame a partir de un fichero .csv de entrada """
def generaDataFrame(dataset):
    try:
        # Convertimos el dataset en un DataFrame:
        dataFrame=pd.read_csv(dataset,sep=';')
        dataFrame= dataFrame.fillna(0)
        to_model_columns=dataFrame.columns[1:17]
        dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)
        return dataFrame
    except FileNotFoundError:
        print(f"No se ha encontrado el Dataset {dataset}")
        exit(0)


""" Se obtiene la actividad maxima de cada feature del dataset"""
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
            print("VALORES MAXIMOS DE CADA FEATURE DEL DATASET")
            headers = "MAC[NUM_MAC;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP]"
            print(headers)
            imprimeActMacs(mac_maxAct)


""" Tunear los datos de cada feature en un tanto por uno. Resultado redondeado a enteros"""
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
            print("La MAC especificada no se encuentra en el dataset")


"""Generamos las lineas del dataset con formato. Ordenamos de mas actividad a menor actividad."""
def imprimeActMacs(param):
    for key, value in sorted(param.items(), key=lambda item: item[1][0], reverse=True):
        print(key, end=";")
        print(';'.join(map(str,value))) 


if __name__ == '__main__':
    text_help= "Genera outliers de una mac en un dataset determinado."
    text_help += "\n\t./tunea_entradas.py -d dataset.csv -> Visualiza el valor maximo de cada feature del dataset de las MACs"
    text_help += "\n\t./tunea_entradas.py -d dataset.csv -m 000fXXXXXXXX -t 0.4 -> Incrementa el valor de los campos en un 40% de la MAC 000fXXXXXXXX"
    text_help += "\n\t./tunea_entradas.py -d dataset.csv -t 0.4 -> Incrementa el valor de los campos de todas las MACs en un 40%"
    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-m", "--MAC", required=False, help="Direccion MAC")
    ap.add_argument("-t", "--tunea", required=False, help="Tunear los datos en un tanto por cento de su valor inicial")
    ap.add_argument("-d", "--Dataset", required=False, help="Dataset")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])
    if args.Dataset:
        dataset = vars(ap.parse_args())["Dataset"]
        dataFrame = generaDataFrame(dataset)
        if len(sys.argv) - 1 < 3:
            ActMaxMacs(dataFrame, True)
        else:
            ActMaxMacs(dataFrame)

        if args.tunea:
            dir_mac = vars(ap.parse_args())["MAC"]
            porcentaje = vars(ap.parse_args())["tunea"]
            # Por defecto el porcentaje sera de un 20%
            if porcentaje is None:
                tunea_datos(dir_mac, porcentaje=0.2)
            else:
                tunea_datos(dir_mac, porcentaje)
