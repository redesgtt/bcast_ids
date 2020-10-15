#! /usr/bin/env python3
import argparse
import pickle
import sys
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.model_selection import train_test_split

""" Funcion principal de entrenamiento del algoritmo Isolation Forest """
def train_if(dataset, c, filename='model_iso_forest.bin'):
    print("Inicio del entrenamiento...")

    name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

    # Leemos el fichero:
    df = pd.read_csv(dataset,sep=';',names=name_columns)
    df = df.fillna(0)
    to_model_columns=df.columns[1:19]
    df[to_model_columns] = df[to_model_columns].astype(int)
    if contamination == 'auto':
        classifier = IsolationForest(bootstrap=False, contamination='auto', max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False, behaviour='new')
    else:
        classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)

    classifier.fit(df[to_model_columns])

    pickle.dump(classifier, open(filename, 'wb'))
    print(f'\nMODELO {filename} guardado en directorio actual')

    # Predecimos las actividades de la MAC del algoritmo ya entrenado
    pred = classifier.predict(df[to_model_columns])
    df['ANOMALY']=pred
    outliers=df.loc[df['ANOMALY']==-1]

    print("\t\nANOMALIAS:")
    print(outliers.head)

    print("\t\nRECUENTO:")
    print(df['ANOMALY'].value_counts())


if __name__ == '__main__':
    text_help= "Script para entrenar el algoritmo Isolation Forest sobre un conjunto de datos de entrada. Ejemplos:"
    text_help += "\n\t./train_iso_forest.py -d dataset22.csv"
    text_help += "\n\t./train_iso_forest.py -d dataset22.csv -c 0.0002456"
    text_help += "\nSALIDA"
    text_help += "\n\t[+] model_iso_forest.bin -> modelo entrenado \n\n"

    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-d", "--dataset", required=True, help="Dataset de entrada para entrenar al algoritmo")
    ap.add_argument("-c", "--contamination", required=False, help="Contamination: estima el tanto por uno de anomalias presentes en el dataset")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.dataset:
        file = vars(ap.parse_args())["dataset"]
        contamination = vars(ap.parse_args())["contamination"]
        if contamination != None:
            if float(contamination) > float(0.5) or float(contamination) < 0:
                print("\t\nERROR! El parametro CONTAMINATION tiene que estar en el rango [0, 0.5]\n")
            else:
                print(f'\nENTRENAMOS MODELO CON CONTAMINATION {contamination} \n')
                train_if(file, float(contamination))
        else:
            contamination = 'auto'
            print(f'\nENTRENAMOS MODELO CON CONTAMINATION {contamination}. \n')
            train_if(file, contamination)
