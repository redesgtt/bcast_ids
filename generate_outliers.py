#!/usr/bin/env python3.6

from numpy.random import seed
from numpy.random import randint
import numpy as np
import pandas as pd
import argparse
import sys
import os

# Diccionario mac_maxAct
mac_maxAct = dict()
name_columns = ['MAC','NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

# TYPICAL NETWORK SCANNING ATTACK
def generateOutliers(num):

    lista_actividad = []
    percentaje = 0.020 # Variacion

    # PORT SCANNING:
    for i in range(num):
        l = [0] * 18
        l[0] = randint(260, 800)
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
        l[8] = randint(0, 10)
        l[9] = randint(0, 1)
        l[10] = randint(0, 20)
        l[12] = randint(0, 5)
        l[13] = randint(0, 8)
        l[14] = randint(0, 2)
        l[15] = randint(170, 254)
        ssdp = randint(0, 8)
        if ssdp <= l[10]:
            l[16]= ssdp
        else:
            l[16] = 0
        icmpv6 = randint(0, 3)
        if icmpv6 <= l[13]:
            l[17] = icmpv6
        else:
            l[17] = 0
        l = ['automated_outlier'] + l
        print(l)
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
        print("Error de lectura del dataset")

    finally:
        return dataFrame
