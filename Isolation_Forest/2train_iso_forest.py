#!/usr/bin/env python3.6
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

    # Leemos el fichero:
    df = pd.read_csv(dataset,sep=';')
    df = df.fillna(0)
    to_model_columns=df.columns[1:17]
    df[to_model_columns] = df[to_model_columns].astype(int)    
    classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
    classifier.fit(df[to_model_columns])

    pickle.dump(classifier, open(filename, 'wb'))
    print(f'\nMODELO {filename} guardado en directorio actual\n')

    # Predecimos las actividades de la MAC del algoritmo ya entreado
    pred = classifier.predict(df[to_model_columns])
    df['IF']=pred
    outliers=df.loc[df['IF']==-1]

    print("\t\nANOMALIAS:")
    print(outliers)

    print("\t\nRECUENTO:")    
    print(df['IF'].value_counts())


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
            if float(contamination) > 1 or float(contamination) < 0:
                print("\t\nERROR! El parametro CONTAMINATION ha de estar entre 1 y 0.\n")
            else:
                print(f'\nENTRENAMOS MODELO CON CONTAMINATION {contamination} \n')
                train_if(file, float(contamination))            
        else:
            #contamination = 0.002438
            contamination = 0.1
            print(f'\nENTRENAMOS MODELO CON CONTAMINATION {contamination} \n')
            train_if(file, contamination)
