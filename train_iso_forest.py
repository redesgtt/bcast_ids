#! /usr/bin/env python3
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
name_columns = ['MAC', 'NUM_MACS', 'UCAST', 'MCAST', 'BCAST','ARPrq','ARPpb','ARPan','ARPgr','IPF','IP_ICMP','IP_UDP','IP_TCP','IP_RESTO','IP6','ETH_RESTO','ARP_noIP','SSDP','ICMPv6']

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

            if c == 'auto':
                # c = num of ARP_noIP columns largest than 40 (its value is large in network scanning tools) / total rows in the dataset
                df_noMAC = df.drop(['MAC'] , axis=1)
                c = df_noMAC[df_noMAC > 40 ].count()['ARP_noIP'] / len(df_noMAC.axes[0])
                print("Calculation of the contamination parameter = num ARP_noIP columns largest than 40 / total rows in the dataset")
                print(f"Contamination: {df_noMAC[df_noMAC > 40 ].count()['ARP_noIP']} / {len(df_noMAC.axes[0])} = {float(c)}")
                classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
            else:
                classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
            # Trainning and prediction of the results
            pred = classifier.fit_predict(df[to_model_columns])

            # Print the outliers detected
            outliers=df.loc[pred==-1]
            print("\t\nOUTLIERS:")
            print(outliers)

            # Count normal and abnormal points:
            print("\t\nCOUNT: (1 actividad normal / -1 anomalias)")
            df['ANOMALY']=pred
            print(df['ANOMALY'].value_counts())

            # Saving the model
            try:
                pickle.dump(classifier, open(filename, 'wb'))
                print(f'\nMODEL saved in the actual directory: {os.getcwd()}/{filename}')
            except:
                print("ERROR! The Machine Learning model could not be saved")
        except FileNotFoundError:
            print("ERROR! Wrong file or file path")
    except:
        print("Training could not be performed correctly")


""" To train the Isolation Forest algorithm from the main program automatically. Return if the training was succesful or not and the value of contamination """
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
                    # We obtain the contamination parameter if ARP_noIP is biggest than 20
                    df_noMAC = df.drop(['MAC'] , axis=1)
                    # c = num of ARP_noIP columns largest than 20 (its value is large in network scanning tools) / total rows in the dataset
                    if df_noMAC[df_noMAC > 40 ].count()['ARP_noIP'] > 0:
                        c = df_noMAC[df_noMAC > 40 ].count()['ARP_noIP'] / len(df_noMAC.axes[0])
                        classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
                    else:
                        classifier = IsolationForest(bootstrap=False, contamination='auto', max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)
                else:
                    classifier = IsolationForest(bootstrap=False, contamination=float(c), max_features=1.0, max_samples='auto', n_estimators=100, n_jobs=None, random_state=42, warm_start=False)

            # Train and predict the anomalies detected in the dataset
            pred = classifier.fit_predict(df[to_model_columns])

            # We save the model in .bin format
            pickle.dump(classifier, open(filename, 'wb'))

            # GENERATE OUTLIERS set to 'yes'
            if generate_outliers:
                message = (f"{dia} {hora} - GENERATE_OUTLIERS set to 'yes'. Automated training was successful with contamination {c}. ML model created at {os.getcwd()}/{filename}\n"
                f"\t\t   RESULTS: {len(df_outliers.axes[0])} anomalies generated / {len(df.loc[pred==-1].axes[0])} anomalies detected = {len(df_outliers.axes[0])/len(df.loc[pred==-1].axes[0]) * 100} % accuracy.\n"
                f"The anomalies detected were: \n {df.loc[pred==-1].to_string()} \n\n"
                )
                #print(message)
            # GENERATE OUTLIERS set to 'no'
            else:
                # Show the results:
                message = (f"{dia} {hora} - GENERATE_OUTLIERS set to 'no'. Automated training was successful with contamination {c}. ML model created at {os.getcwd()}/{filename}\n"
                f"\t\t   RESULTS: {len(df.loc[pred==-1].axes[0])} anomalies detected in the first {len(df.axes[0])} rows of the {dataset} at the time of automated training.\n"
                f"The anomalies detected were: \n {df.loc[pred==-1].to_string()} \n\n"
                )
                #print(message)

        else:
            message = f"{dia} {hora} - ERROR! Dataset is empty. Automated training was not successful. Model was NOT created. \n"
            train_successful = False
    except Exception as e:
        message = f"{dia} {hora} - ERROR! Exception captured: {e}. Automated training was not successful. Model was NOT created. \n"
        train_successful = False
    finally:
        #return train_successful,c
        return message

if __name__ == '__main__':
    text_help= "Script to train the Isolation Forest algorithm on a dataset. Examples:"
    text_help += "\n\t./train_iso_forest.py -d dataset22.csv"
    text_help += "\n\t./train_iso_forest.py -d dataset22.csv -c 0.0002456"
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
                    print(f'\nTrainning the model with contamination {contamination} \n')
                    #train_dataset(file, float(contamination))
                    train_capture(file, float(contamination))
            except:
                print("ERROR! Please enter a valid contamination number. Remember that it has to be in the range [0, 0.5] or 'auto'")
        else:
            contamination = 'auto'
            print(f'\nTrainning the model with contamination {contamination}. \n')
            train_dataset(file, contamination)
