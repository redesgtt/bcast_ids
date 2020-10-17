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

name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

""" Para entrenar al algoritmo de Isolation Forest de manera manual """
def train_dataset(dataset, c='auto', filename='model_iso_forest.bin'):
    global name_columns
    print("Inicio del entrenamiento...")

    try:
        # Leemos el fichero csv y preparamos los datos para el entrenamiento:
        try:
            df = pd.read_csv(dataset,sep=';',names=name_columns)
            df = df.fillna(0)
            to_model_columns=df.columns[1:19]
            df[to_model_columns] = df[to_model_columns].astype(int)
            if c == 'auto':
                classifier = IsolationForest(bootstrap=False, contamination='auto', max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
            else:
                classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
                # Entrenamiento y prediccion de los resultados
            pred = classifier.fit_predict(df[to_model_columns])

            # Imprimimos las anomalias detectadas en pantalla
            outliers=df.loc[pred==-1]
            print("\t\nANOMALIAS:")
            print(outliers)

            # Imprimimos recuento de anomalias total:
            print("\t\nRECUENTO: (1 actividad normal / -1 anomalias)")
            df['ANOMALY']=pred
            print(df['ANOMALY'].value_counts())

            # Guardamos modelo
            try:
                pickle.dump(classifier, open(filename, 'wb'))
                print(f'\nMODELO {filename} guardado en directorio actual')
            except:
                print("ERROR! No se ha podido guardar el modelo")
        except:
            print("ERROR! Fallo en la lectura del dataset. ¿Has comprobado que exista en el mismo directorio y/o tenga el formato adecuado?")
    except:
        print("No se ha podido realizar correctamente entrenamiento")


""" Para entrenar al algoritmo Isolation Forest desde el programa principal automaticamente """
def train_capture(dataset, c, filename='model_iso_forest.bin'):
    global name_columns
    train_successful = True

    try:
        # Leemos el fichero y agregamos columnas
        df = pd.read_csv(dataset,sep=';',names=name_columns)
        df = df.fillna(0)
        to_model_columns=df.columns[1:19]
        df[to_model_columns] = df[to_model_columns].astype(int)

        # Iniciamos el entrenamiento del algoritmo
        if c == 'auto':
            classifier = IsolationForest(bootstrap=False, contamination='auto', max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
        else:
            classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)

        classifier.fit(df[to_model_columns])

        # Guardamos el modelo en formato .bin
        pickle.dump(classifier, open(filename, 'wb'))
    except:
        train_successful = False
    finally:
        return train_successful

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
            try:
                if float(contamination) > float(0.5) or float(contamination) < 0:
                    print("\t\nERROR! El parametro CONTAMINATION tiene que estar en el rango [0, 0.5]\n")
                else:
                    print(f'\nENTRENAMOS MODELO CON CONTAMINATION {contamination} \n')
                    train_dataset(file, float(contamination))
            except:
                print("ERROR! Introduce un numero de contamination valido. Recuerda que tiene que estar en el rango [0, 0.5] o 'auto'")
        else:
            contamination = 'auto'
            print(f'\nENTRENAMOS MODELO CON CONTAMINATION {contamination}. \n')
            train_dataset(file, contamination)
