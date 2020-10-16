#! /usr/bin/env python3
import argparse
import sys
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import warnings

def load_model(filename):
    try:
        # Cargar el modelo desde el disco
        loaded_model = pickle.load(open(filename, 'rb'))
        return loaded_model
    except:
        return None

""" Prediccion de la actividad de un conjunto de direcciones MAC. Devuelve una lista de las MACs anomalas de la captura en curso"""
def predict_capture(dataset):
    loaded_model = load_model("./model_iso_forest.bin")
    macs_atacando = list()
    if loaded_model != None:
        try:
            name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

            # Leemos los datos de la captura
            dataFrame = pd.DataFrame(dataset,columns=name_columns)

            # Excluimos la celda MAC para realizar la prediccion
            to_model_columns=dataFrame.columns[1:19]
            dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)

            # Realizamos la prediccion
            prediction = loaded_model.predict(dataFrame[dataFrame.columns[1:19]])
            dataFrame['IF']=prediction

            # Imprimimos las direcciones MACs que estan atacando
            macs_atacando = dataFrame.loc[dataFrame['IF']==-1]['MAC'].tolist()

        except FileNotFoundError:
            msg = "Vaya... Parece que no se encuentra el fichero {0}.".format(dataset)
            print(msg)

        finally:
            return macs_atacando

    else:
        print("ERROR! No se ha podido cargar el modelo")
        return macs_atacando


def predict_if(cad, filename):
    if filename == None:
        loaded_model = load_model("./model_iso_forest.bin")
    else:
        loaded_model = load_model(filename)

    if loaded_model != None:
        # Cabecera:
        headers = "MAC;NUM_MACS;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP;SSDP;ICMPv6"
        # Convertimos los datos a un DataFrame para poder predecir el resultado:
        d = dict()
        for i in range(len(headers.split(";"))):
            if i == 0:
                d[headers.split(";")[i]]=[(cad.split(";"))[i]]
            else:
                d[headers.split(";")[i]]=[int(cad.split(";")[i])]
        df = pd.DataFrame(data=d)

        traff_dif = df.iloc[ : ,1:19]
        #traff_dif = df.drop(['IP_TCP','ARPpb','ARPan','MAC','IP_UDP','IP6','UCAST','MCAST'], axis=1)
        try:
            # Resultado de la prediccion:
            prediction = loaded_model.predict(traff_dif)
            print(prediction)
        except:
            print("No se ha podido realizar la prediccion")
    else:
        print("No se ha podido cargar el modelo")

def predict_dataset_if(dataset, filename):
    if filename == None:
        loaded_model = load_model("./model_iso_forest.bin")
    else:
        loaded_model = load_model(filename)

    if loaded_model != None:
        try:
            name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']
            dataFrame=pd.read_csv(dataset,sep=';',names=name_columns)
            dataFrame= dataFrame.fillna(0)
            to_model_columns=dataFrame.columns[1:19]
            dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)
            dataFrame_aux = dataFrame[dataFrame.columns[1:19]]
            prediction = loaded_model.predict(dataFrame_aux)
            count_normal = 0;
            count_anomaly = 0;
            for p in prediction:
                if p == 1:
                    count_normal += 1
                else:
                    count_anomaly += 1
            print("------------------------------------")
            print(f"Cantidad de MACS con actividad Normal: {count_normal}")
            print(f"Cantidad de MACs con actividad Anormal: {count_anomaly}")
            print("------------------------------------")

            dataFrame['IF']=prediction
            outliers=dataFrame.loc[dataFrame['IF']==-1]
            print(outliers.to_string())

        except FileNotFoundError:
            msg = "Vaya... Parece que no se encuentra el fichero {0}.".format(dataset)
            print(msg)
    else:
        print(f"No se ha podido cargar el modelo")

if __name__ == '__main__':
    text_help= "Script para realizar la prediccion del modelo Isolation Forest entrenado."
    text_help += "\n\t./predict_iso_forest.py -s \"000fxxxxxxx;257;1;5;251;251;0;0;0;5;0;0;0;1;5;0;246;0;5\""
    text_help += "\n\t./predict_iso_forest.py -s \"000fxxxxxxx;257;1;5;251;251;0;0;0;5;0;0;0;1;5;0;246;0;5\" -m modelo.bin"
    text_help += "\n\t./predict_iso_forest.py -d dataset30.csv"
    text_help += "\n\t./predict_iso_forest.py -d dataset30.csv -m modelo.bin"
    text_help += "\nSALIDA"
    text_help += "\n\t[+]  1 -> no ataque \n"
    text_help += "\t[+] -1 -> ataque \n\n"
    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-s", "--actividadMAC", required=False, help="Linea de actividad de una direccion MAC")
    ap.add_argument("-d", "--datasetMAC", required=False, help="Dataset de actividad de direcciones MAC")
    ap.add_argument("-m", "--model", required=False, help="Modelo de ML")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.actividadMAC:
        model_file = vars(ap.parse_args())["model"]
        cad = vars(ap.parse_args())["actividadMAC"]
        predict_if(cad,model_file)
    if args.datasetMAC:
        model_file = vars(ap.parse_args())["model"]
        dataset = vars(ap.parse_args())["datasetMAC"]
        predict_dataset_if(dataset,model_file)
        #predict_capture(dataset)
