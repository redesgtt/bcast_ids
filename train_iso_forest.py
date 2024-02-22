#! /usr/bin/env python3

##############################################################################################
#                        BCAST_IDS: A NETWORK INTRUSION DETECTION SYSTEM
#                           TRAINING WITH ISOLATION FOREST ALGORITHM
#
#                                      Dpto de Redes
#                               Gestion Tributaria Territorial
#                                           2020
##############################################################################################

import argparse
import pickle
import sys
import os
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.model_selection import train_test_split
from generate_outliers import outliers_to_dataframe

dia = datetime.today().strftime('%d/%m/%Y')
hora = datetime.today().strftime('%H:%M')
name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARP','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

# Type the columns you want to delete in the training phase
delete_columns = ['MAC']c


""" To train the Isolation Forest algorithm manually """
def train_dataset(dataset, c='auto', filename='model_iso_forest.bin'):
    global name_columns
    print("Initializing the training...")

    try:
        # Read the dataset and prepare the data
        try:
            df = pd.read_csv(dataset,sep=';',names=name_columns)
            df = df.fillna(0)
            to_model_columns=df.columns[1:19]
            df[to_model_columns] = df[to_model_columns].astype(int)
            df_aux = df.drop(delete_columns, axis=1)

            if c == 'auto':
                # In this section, we consider an anomaly if a row has the ARP_noIP value greater than 40
                c = df_aux[df_aux > 40 ].count()['ARP_noIP'] / len(df_aux.axes[0])
                print("Calculation of the contamination parameter = num ARP_noIP columns largest than 40 / total rows in the dataset")
                print(f"Contamination: {df_aux[df_aux > 40 ].count()['ARP_noIP']} / {len(df_aux.axes[0])} = {float(c)}")
                classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
            else:
                classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)

            print(f"Training bear in mind these columns: {(df_aux.columns.tolist())}")

            # Trainning and prediction of the results
            pred = classifier.fit_predict(df_aux)

            # Print the outliers detected
            outliers=df.loc[pred==-1]
            print("\t\nOUTLIERS:")
            print(outliers.to_string())

            # Count normal and abnormal points:
            print("\t\nCOUNT: (1 actividad normal / -1 anomalias)")
            df_aux['ANOMALY']=pred
            print(df_aux['ANOMALY'].value_counts())

            # Saving the model
            try:
                pickle.dump(classifier, open(filename, 'wb'))
                print(f'\nMODEL saved in the actual directory: {os.getcwd()}/{filename}')
            except:
                print("ERROR! The Machine Learning model could not be saved")
        except FileNotFoundError:
            print("ERROR! Wrong file or file path")
    except Exception as e:
        print(e)


""" In order to train Isolation Forest algorithm from the main program automatically. Return an string if the training was succesful or not and the value of contamination """
def train_capture(dataset, c, generate_outliers=True, filename='model_iso_forest.bin'):
    global name_columns
    train_successful = True
    message = f"{dia} {hora} - ERROR! Automated training was not successful. Model was NOT created. \n"

    try:
        # Read the dataset and prepare the data
        df = pd.read_csv(dataset,sep=';',names=name_columns)

        # Outliers dataFrame:
        df_outliers = pd.DataFrame(columns=name_columns)

        if not df.empty:
            df = df.fillna(0)
            to_model_columns=df.columns[1:19]
            df[to_model_columns] = df[to_model_columns].astype(int)
            df_aux = df.drop(delete_columns, axis=1)

            # In order to generate outliers automatically:
            if generate_outliers:
                # Num anomalies:
                if c != 'auto':
                    num_anomalies = round(float(c) * len(df.axes[0]))
                    df_outliers = outliers_to_dataframe(num_anomalies)
                else:
                    c = float(0.01)
                    num_anomalies = round(c * len(df.axes[0]))
                    df_outliers = outliers_to_dataframe(num_anomalies)

                if not df_outliers.empty:
                    df = df.append(df_outliers, ignore_index=True)

                if c != 'auto':
                    classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
                else:
                    classifier = IsolationForest(bootstrap=False, contamination=0.1, max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)

            # Generate the outliers manually:
            else:
                if c == 'auto':
                    # In this section, we consider an anomaly if a row has the ARP_noIP value greater than 40
                    num_anomalies_in_dataset = df_aux[df_aux > 40 ].count()['ARP_noIP']
                    if num_anomalies_in_dataset > 0:
                        new_c = num_anomalies_in_dataset / len(df.axes[0])
                        classifier = IsolationForest(bootstrap=False, contamination=float(new_c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
                    else:
                        classifier = IsolationForest(bootstrap=False, contamination='auto', max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
                else:
                    classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)

            df_aux = df.drop(delete_columns, axis=1)

            # Train and predict the anomalies detected in the dataset
            pred = classifier.fit_predict(df_aux)

            # We save the model in .bin format
            pickle.dump(classifier, open(filename, 'wb'))

            # GENERATE OUTLIERS set to 'yes'
            if generate_outliers:
                message = (f"{dia} {hora} - GENERATE_OUTLIERS set to 'yes'. Automated training was successful with contamination {c}. ML model created at {os.getcwd()}/{filename}\n"
                f"\t\t   Using the first {len(df.axes[0])} rows of the {dataset} at the time of automated training \n"
                f"\t\t   RESULTS: {len(df_outliers.axes[0])} anomalies generated / {len(df.loc[pred==-1].axes[0])} anomalies detected = {len(df_outliers.axes[0])/len(df.loc[pred==-1].axes[0]) * 100} % accuracy \n"
                f"The anomalies detected were: \n {df.loc[pred==-1].to_string()} \n\n"
                )
            # GENERATE OUTLIERS set to 'no'
            else:
                # Show the results:
                message = (f"{dia} {hora} - GENERATE_OUTLIERS set to 'no'. Automated training was successful with contamination {c}. ML model created at {os.getcwd()}/{filename}\n"
                f"\t\t   RESULTS: {len(df.loc[pred==-1].axes[0])} anomalies detected in the first {len(df.axes[0])} rows of the {dataset} at the time of automated training.\n"
                f"The anomalies detected were: \n {df.loc[pred==-1].to_string()} \n\n"
                )
        else:
            message = f"{dia} {hora} - ERROR! Dataset is empty. Automated training was not successful. Model was NOT created. \n"
            train_successful = False
    except Exception as e:
        message = f"{dia} {hora} - ERROR! Exception captured: {e}. Automated training was not successful. Model was NOT created. \n"
        train_successful = False
    finally:
        return message

if __name__ == '__main__':
    text_help= "Script to train the Isolation Forest algorithm on a dataset. Examples:"
    text_help += "\n\t./train_iso_forest.py -d dataset.csv"
    text_help += "\n\t./train_iso_forest.py -d dataset.csv -c 0.0002456"
    text_help += "\nOUTPUT"
    text_help += "\n\t[+] model_iso_forest.bin -> trained ML model \n\n"

    ap = argparse.ArgumentParser(text_help)
    ap.add_argument("-d", "--dataset", required=True, help="Name of the dataset")
    ap.add_argument("-c", "--contamination", required=False, help="Contamination: it specifies the percentage of observations we believe to be outliers (from 0.0 to 0.5)")
    args = ap.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.dataset:
        file = vars(ap.parse_args())["dataset"]
        contamination = vars(ap.parse_args())["contamination"]
        if contamination != None:
            try:
                if float(contamination) > float(0.5) or float(contamination) < 0:
                    print("\t\nERROR! The CONTAMINATION parameter must be in the range [0, 0.5]\n")
                else:
                    print(f'\nTraining the model with contamination {contamination} \n')
                    train_dataset(file, float(contamination))
            except:
                print("ERROR! Please enter a valid contamination number. Remember that it has to be in the range [0, 0.5] or 'auto'")
        else:
            contamination = 'auto'
            print(f'\nTraining the model with contamination {contamination}. \n')
            train_dataset(file, contamination)
