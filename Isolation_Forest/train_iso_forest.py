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
from sklearn.metrics import classification_report,accuracy_score


""" Funcion principal de entrenamiento del algoritmo Isolation Forest """
def train_if(dataset, c, filename='model_iso_forest.bin'):
    try:
        print("Inicio del entrenamiento...")

        dataFrame=pd.read_csv(dataset,sep=';')
        dataFrame= dataFrame.fillna(0)
        to_model_columns=dataFrame.columns[1:17]
        dataFrame[to_model_columns] = dataFrame[to_model_columns].astype(int)

        y = dataFrame['SALIDA']
        X = dataFrame[dataFrame.columns[1:17]]
        #X = dataFrame.drop(['MAC','UCAST','SALIDA','BCAST','ARPpb','ARPgr','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO'], axis=1)
        X_train, X_test, y_train, y_test = train_test_split(X, y,test_size=0.2)
        print (" Training data set : ",X_train.shape)
        print (" Test data set : ",X_test.shape)
        print (" Number of Anomaly cases in training set : ",len(y_train[y_train==1]))
        print (" Number of Anomaly cases in test set : ",len(y_test[y_test==1]))

        # Generamos el parametro contamination
        if c == None:
            try:
                lines_attack_train = len(y_train[y_train==1])
                lines_noattack_train = len(y_train[y_train==0])
                c = float(lines_attack_train/lines_noattack_train)
                print(f'\nENTRENAMOS MODELO CON CONTAMINATION {lines_attack_train} / {lines_noattack_train} = {c} \n')
            except ZeroDivisionError:
                print("El dataset solo contiene entradas de ataques (SALIDA=1). Introduce tambien datos sin ataques!")
                exit(0)
        else:
            print(f'\nENTRENAMOS MODELO CON CONTAMINATION {c} \n')

        number_of_train_samples=len(X_train)

        # Ajustamos el modelo
        classifier=IsolationForest(n_estimators=100, max_samples=number_of_train_samples,contamination=c,random_state=None, verbose=0)
        classifier.fit(X_train)

        #Prediccion en el train set
        y_pred_train = classifier.predict(X_train)
        #Prediccion en el test set
        y_pred_test = classifier.predict(X_test)

        generate_report(y_test, y_train, y_pred_train, y_pred_test)

        print("-----------------------------------------------------------")
        pickle.dump(classifier, open(filename, 'wb'))
        print(f'\nMODELO {filename} guardado en directorio actual\n')
    except FileNotFoundError:
        print(f"No se ha encontrado el fichero {dataset}")


def generate_report(y_test, y_train, y_pred_train, y_pred_test):
    # Cambiamos la salida del programa a 1 (ataque) y a 0 (no ataque ) para generar un informe de rendimiento del algoritmo
    y_pred_train[y_pred_train == 1] = 0
    y_pred_train[y_pred_train == -1] = 1
    y_pred_test[y_pred_test == 1] = 0
    y_pred_test[y_pred_test == -1] = 1
    print("-----------------------------------------------------------")
    print(" Score on Test set")
    print(" Error count : ",(y_test!=y_pred_test).sum())
    print(" Accuracy Score:")
    print(accuracy_score(y_test,y_pred_test))
    print(" Classification Report:")
    print(classification_report(y_test,y_pred_test))
    print("\n-----------------------------------------------------------")
    print(" Score on training set")
    print(" Error count : ",(y_train != y_pred_train).sum())
    print(" Accuracy Score:")
    print(accuracy_score(y_train,y_pred_train))
    print(" Classification Report:")
    print(classification_report(y_train,y_pred_train))


if __name__ == '__main__':
    text_help= "Script para entrenar el algoritmo Isolation Forest sobre un conjunto de datos de entrada. Ejemplos:"
    text_help += "\n\t./train_iso_forest.py -d dataset33.csv"
    text_help += "\n\t./train_iso_forest.py -d dataset33.csv -m modelo.bin"
    text_help += "\n\t./train_iso_forest.py -d dataset33.csv -c 0.0002456"
    text_help += "\n\t./train_iso_forest.py -d dataset33.csv -c 0.0002456 -m modelo.bin" 
    text_help += "\nSALIDA"
    text_help += "\n\t[+] model_iso_forest.bin -> modelo entrenado por defecto"
    text_help += "\n\t[+] modelo.bin -> modelo entrenado por parametro \n\n"

    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-d", "--dataset", required=True, help="Dataset de entrada para entrenar al algoritmo")
    ap.add_argument("-c", "--contamination", required=False, help="Contamination: estima el tanto por uno de anomalias presentes en el dataset")
    ap.add_argument("-m", "--model", required=False, help="Nombre del modelo de ML para guardar")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.dataset:
        file = vars(ap.parse_args())["dataset"]
        model = vars(ap.parse_args())["model"]
        contamination = vars(ap.parse_args())["contamination"]
        if contamination != None:
            if float(contamination) > 1 or float(contamination) < 0:
                print("\t\nERROR! El parametro CONTAMINATION ha de estar entre 1 y 0.\n")
            else:
                if model != None:
                    train_if(file, float(contamination), model)
                else:
                    train_if(file, float(contamination))
        else:
            contamination = None
            if model != None:
                train_if(file, contamination, model)
            else:
                train_if(file, contamination)
