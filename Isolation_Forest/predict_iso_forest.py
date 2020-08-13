#!/usr/bin/env python3.6
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

def predict_if(cad, filename):
    if filename == None:
        loaded_model = load_model("./model_iso_forest.bin")
    else:
        loaded_model = load_model(filename) 

    if loaded_model != None:
        # Cabecera:
        headers = "MAC;NUM_MAC;UCAST;MCAST;BCAST;ARPrq;ARPpb;ARPan;ARPgr;IPF;IP_ICMP;IP_UDP;IP_TCP;IP_RESTO;IP6;ETH_RESTO;ARP_noIP"
        # Convertimos los datos a un DataFrame para poder predecir el resultado:
        d = dict()
        for i in range(len(headers.split(";"))):
            if i == 0:
                d[headers.split(";")[i]]=[(cad.split(";"))[i]]
            else:
                d[headers.split(";")[i]]=[int(cad.split(";")[i])]
        df = pd.DataFrame(data=d)

        # Obtenemos la cantidad total de MACs y el trafico Unicast, Multicast, Broadcast, ARP request, ARP probe y ARPan
        traff_dif = df.iloc[ : ,1:18]
        #traff_dif = df.drop(['IP_TCP','ARPpb','ARPan','MAC','IP_UDP','IP6','UCAST','MCAST'], axis=1)
        try:
            # Resultado de la prediccion:
            prediction = loaded_model.predict(traff_dif)
            print(prediction)
        except:
            print("No se ha podido realizar la prediccion")
    else:
        print("No se ha podido carga el modelo")

def predict_dataset_if(dataset, filename):
    if filename == None:
        loaded_model = load_model("./model_iso_forest.bin")
    else:
        loaded_model = load_model(filename)

    if loaded_model != None:
        try:
            dataFrame=pd.read_csv(dataset,sep=';')
            dataFrame= dataFrame.fillna(0)
            to_model_columns=dataFrame.columns[1:18]
            dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)
            dataFrame_noSALIDA = dataFrame[dataFrame.columns[1:17]]
            #dataFrame_noSALIDA = dataFrame.drop(['IP_TCP','ARPpb','ARPan','MAC','SALIDA','IP_UDP','IP6','UCAST','MCAST'], axis=1)
            #dataFrame_noSALIDA = dataFrame.drop(['MAC','NUM_MAC','SALIDA','IP_UDP','IP6','MCAST', 'ARPpb', 'ARPan','UCAST','MCAST'], axis=1)
            prediction = loaded_model.predict(dataFrame_noSALIDA)
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
    text_help += "\n\t./predict_iso_forest.py -s \"000ffec58a53;254;0;0;254;253;0;1;0;0;0;0;0;0;0;0;0\""
    text_help += "\n\t./predict_iso_forest.py -s \"000ffec58a53;254;0;0;254;253;0;1;0;0;0;0;0;0;0;0;0\" -m modelo.bin"
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
