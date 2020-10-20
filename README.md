# BCAST_IDS: A Network Intrusion Detection System with Machine Learning
*Gestión Tributaria Territorial (GTT), Network dept., Alicante (Spain), 2020*
## Abstract
Network intrusion is a growing threat with severe impacts, which can damage in several ways to network infrastructures and digital assets in the well-known cyberspace. A modern technique employed to combat against network intrusion is the development of attack detection systems using Machine Learning and Data Mining. These approaches can help to protect networks because they are able to identify and disconnect malicious network traffic. BCAST_IDS is a Network Intrusion Detection System (NIDS), which attempts to identify unauthorized and anomalous behaviour in a Local Area Network (LAN) looking at the broadcast and unicast traffic. For that, it monitors network activity on one network segment. Then, the system constantly performs analysis and watches for certain traffic patterns. If the detected traffic patterns match the defined policies in the Machine Learning model, a security alert will be generated.

## Description
Machine Learning and Data Mining techniques work by establishing an implicit or explicit model which enables to categorize the analized patterns. Since network intrusion and Malware activities can be considered as anomalies (outliers), BCAST_IDS uses an unsupervised Machine Learning algorithm, called [**Isolation Forest**](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html), that explicitly identifies them. In principle, outliers are less frequent than regular observations and are different from them in terms of values (they lie further away from the regular observations in the feature space). 

The aforementioned algorithm is built on the basis of [decision trees](https://scikit-learn.org/stable/modules/tree.html) and the main idea of identifying normal and abnormal activity is in the path length of the tree. A normal point requires more partitions to be identified than abnormal point.

There are three main phases to make this project comes true:
1. **Preprocessing:** feature selection and feature extraction. The data instances that are colleted from the network environment are structured.
2. **Training:** the Machine Learning algorithm is used and extracts patterns from the data collected previously. Then, a system model is built.
3. **Detection:** the monitored traffic data will be used as system input to be compared to the generated system model. If the pattern of the observation is matched with an existing threat, an alarm will be triggered and it will indicate a feasible network intrusion.

The following picture represents an overview of the BCAST_IDS architecture:

![alt text](https://user-images.githubusercontent.com/69505347/91721307-d89dd480-eb98-11ea-9655-6ba4da95e401.png)

### Dataset Generation and Preprocessing
The training dataset is collected from a real-world connected environment. At this point, the main features have to be identified. There are a whole bunch of features that can be monitored by networking tools for network analysis over the network, but some of them could be redundant. So, we have selected nineteen features and are listed below:

| Feature  | Description |
| ------------- | ------------- |
| MAC  | MAC address  |
| num_MAC  | Total network packets generated from a specific MAC address |
| UCAST  | Total UNICAST traffic generated from a specific MAC address |
| MCAST  | Total MULTICAST traffic generated from a specific MAC address  |
| BCAST  | Total BROADCAST traffic generated from a specific MAC address  |
| ARPrq  | Total ARP Request traffic generated from a specific MAC address  |
| ARPpb  | Total ARP Probe traffic generated from a specific MAC address  |
| ARPan  | Total ARP Announcement traffic generated from a specific MAC address  |
| ARPgr  | Total ARP Gratitous traffic generated from a specific MAC address  |
| IPF  | Total ARP Request generated from a specific MAC address to an IP address which exists   |
| IP_ICMP  | Total IP ICMP traffic generated from a specific MAC address  |
| IP_UDP  | Total IP UDP traffic generated from a specific MAC address  |
| IP_TCP  | Total IP TCP traffic generated from a specific MAC address  |
| IP_RESTO  | Other traffic generated from a specific MAC address  |
| IPv6  | Total IPv6 traffic generated from a specific MAC address  |
| ETH_RESTO  | Total ETHERNET traffic generated from a specific MAC address  |
| ARP_noIP  | Total ARP Request generated from a specific MAC address to an IP address which does NOT exist   |
| SSDP  | Total SSDP traffic generated from a specific MAC address   |
| ICMPv6  | Total ICMPv6s traffic generated from a specific MAC address   |

Once the features were determined to fed the Isolation Forest algorithm, the next step is to generate the data. This is typically implemented in stages based first on an attack-free netwok and then a number of attacks until all the classes that need to be considered are fully covered by the dataset. The final dataset will cover distinct attack types and attack-free circumstances. 

## Running the BCAST_IDS
### Hardware Prerequisites
Raspberry Pi or PC with Linux (Debian, Ubuntu, CentOS, Fedora...) connected in LAN or any Wifi network.

### Software Prerequisites
BCAST_IDS requires **`Python 3` branch** and the additional libraries listed below:
```
dpkt psutil numpy pandas sklearn
```

### Configuration files
You can modify the `config.txt` file and fill up the variables on your own. **Time is always represented in seconds**:
```
#####################################################################################
#
#                         BCAST_IDS CONFIGURATION FILE
#
#####################################################################################

# POST.SH
## Allow to generate a dataset (yes/no)
GENERATE_DATASET=yes
FILENAME=dataset
POST=10
IFACE2=eth0

# BCAST_IDS_LITE
NET=192.168.1
EXCLUDE_MACS=
## Update time tip.json, tm.json, externos.json, ti6.json, ipf.json (in seconds)
UPDATE_TIME_JSON_HOUR=3600
## Update time ipm.json (in seconds)
UPDATE_TIME_JSON_12HOURS=43200
## Update time tips-week.json (in seconds)
UPDATE_TIME_JSON_WEEK=604800
## Update time tm-month.json (in seconds)
UPDATE_TIME_JSON_MONTH=2592000
# Enable to generate log files (email_messages.log, macs_abnormal_act.log, messages_training.log, new_macs_detected.log)
GENERATE_LOG_FILES=yes
## Enable auto-training (yes/no)
AUTOMATED_TRAINING=yes
## Time to automate training (in seconds) - 1 hour by default
TIME_AUTOMATED_TRAINING=1800
## Adjust Isolation Forest algorithm parameter (auto, float number: 0 < CONTAMINATION < 0.5)
CONTAMINATION=auto

## Allow sending emails from BCAST_IDS (yes/no) 
SEND_EMAIL=no
MAIL_SERVER=
PORT_MAIL_SERVER=
SENDER_EMAIL=
RECEIVERS_EMAIL=
```
The meaning of each property is detailed below:

| Variable  | Description |
| ------------- | ------------- |
| `GENERATE_DATASET`  | Allow to generate a dataset (yes/no). |
| `FILENAME`  | Name of the dataset. Its name is 'dataset' by default |
| `POST`  | Time interval traffic monitoring. |
| `IFACE2`  | Interface where your computer is connected to your network.  |
| `NET`  | Network range.  |
| `EXCLUDE_MACS`  | MAC addresses to exclude (i.e. the default gateway). If there are two or more, they should separate by ',' i.e. EXCLUDE_MACS=MAC1,MAC2 |
| `UPDATE_TIME_JSON_HOUR`  | Time to update tip.json, tm.json, externos.json, ti6.json, ipf.json. |
| `UPDATE_TIME_JSON_12HOURS`  | Time to update ipm.json. |
| `UPDATE_TIME_JSON_WEEK`  | Time to update tips-week.json. |
| `UPDATE_TIME_JSON_MONTH`  | Time to update tm-month.json. |
| `GENERATE_LOG_FILES`  | Enable to generate log files (email_messages.log, macs_abnormal_act.log, messages_training.log, new_macs_detected.log). |
| `AUTOMATED_TRAINING`  | In order to train the algorithm automatically (yes/no) |
| `TIME_AUTOMATED_TRAINING`  | Countdown to train the algorithm with the current dataset. It takes the last 12.000 entries of the dataset |
| `CONTAMINATION`  | It specifies the percentage of observations we believe to be outliers. It can be two different values: 'auto' or a float number.  If it is set to 'auto', contamination is equal to num of ARP_noIP columns largest than 20 (its value is large in network scanning tools) divided by total rows in the dataset at the time of automated trainning. If it is a number, the parameter must be between 0.0 and 0.5. |
| `SEND_EMAIL`  | Enable or disable to send emails. |
| `MAIL_SERVER`  | Mail server name. |
| `PORT_MAIL_SERVER`  | Port mail server. |
| `SENDER_EMAIL`  | Sender email. |
| `RECEIVERS_EMAIL`  | Receivers mail. If there are two or more, they should separate by ',' i.e. RECEIVERS_EMAIL=mail1@tesbcast.com,mail2@tesbcast.com.  |

### Run the Project

#### Download

```
git clone https://github.com/redesgtt/bcast_ids.git
```
Then you need to install the basic dependencies to run the project on your system:
```
cd bcast_ids
pip3 install -r requirements.txt
```
Wait for the requirements to download, it may take a while. Once they are downloaded, you are good to go!

#### Preprocessing
1. Firstly, make sure you are as a 'root' user and you fill up correctly the variables of config.txt file (`IFACE2`, `NET`, `EXCLUDE_MACS`...). Execute `./post.sh` in order to generate a dataset. Remember that in this phase the variable `GENERATE_DATASET` should set to 'yes'. Keep this script running. If you want to run it at the background you can type `./post.sh &` at the command prompt. Network traffic is analized each 10 seconds by default (`POST` variable).
2. The dataset is now generating and is growing over time. Type `tail -f dataset.csv` at the command prompt to observe it. 
3. It is time to make some kind of **cyberattacks to your own network**. If you are in a Wifi network, try to download any network scanning tool in order to make outliers in the data in your smartphone or Tablet PC. There are plenty of them in the App Store (iOs) or Play Store (Android), i.e. [Net Analyzer](https://play.google.com/store/apps/details?id=net.techet.netanalyzerlite.an&hl=es_419). If want to use a distinct PC computer to perform cyberattacks, you can employ `nmap, arp-scan, netdiscover...`. Make sure that the devices and BCAST_IDS are connected in the same network.
4. Observe the data which is generated in the `dataset.csv`. Combine normal and abnormal entries. It is highly recommended that the file has 10.000-12.000 lines.
6. At the same time, you can also see the .json files. Remember that, their time expiration can be modified in config.txt file through `UPDATE_TIME_JSON_HOUR`, `UPDATE_TIME_JSON_12HOURS`, `UPDATE_TIME_JSON_WEEK` and `UPDATE_TIME_JSON_MONTH` properties:

| JSON  | Description |
| ------------- | ------------- |
| **tip.json**  | {IP source subnet:time}. Active source IPs (v.4) which belong to the network range specified in the `NET` attribute of the config file. |
| **tm.json**  | {MAC source:time}. Active source MACs.  |
| **externos.json**  | {IP source:time}. Active source IPs which do not belong to the network range specified in the `NET` attribute of the config file.  |
| **ti6.json**  | {MAC source:time}. Active source IPs (v.6). |
| **ipf.json**  | {IP source_IP destination:time}. ARP trafic generated between two existing IPs which belong to the network range specified in the 'NET' attribute of the config file. |
| **ipm.json**  |  {MAC source:IP source}. Active source MACs and IPs which have generated ARP traffic in the network range specified in the config file. |
| **tips-week.json**  | {IP source:time}. Active source IPs (v.4) which belong to the network range specified in the `NET` attribute of the config file. It has a week expiration by default. |
| **tm-month.json**  | {MAC source:time}. Active source MACs which have a month expiration by default. |

#### Trainning
##### Automated trainning
1. If there is no a Machine Learning model in the directory which is allocated the bcast_ids project, the system can extract patterns automatically from the data collected at `dataset.csv` so far bear in mind the countdown specified in `TIME_AUTOMATED_TRAINING`. Also, make sure `AUTOMATED_TRAINING` is set to 'yes'. Remember you can Adjust Isolation Forest algorithm parameter in the config file (it is set to 'auto' by default).
2. Once the countdown is over and everything went as expected, a model will be created in the bcast_ids folder with the name 'model_iso_forest.bin' and the results could be checked at the file `training_messages.log`. Otherwise, an message error will appear at the aforementioned log file. 

##### Manual training
1. You can use the script `./train_iso_forest.py` to extract patterns from the data collected in the file `dataset.csv`. Feel free to change the contamination parameter `-c`, that is the proportion of outliers in the dataset. Note that this value must be between 0 and 0.5. Analyze the outliers given by the algorithm.
2. Soon afterward, a model will be generated with the name `model_iso_forest.bin`.
3. Make some tests with the script `./predict_iso_forest.py` and verify the effectiveness of the Isolation Forest algorithm.

#### Detection
1. If the model has saved successfully and you have checked that the outliers detected by the algorithm are appropiate, the BCAST_IDS should detected anomalies un your network! If the algorithm detects any abnormal activity, it will be registered at `macs_abnormal_act.log`. Moreover if the system detects a new MAC in the network which was not in tm-month.json, it will be registered at `new_macs_detected.log`. 
2. Moreover, a network capture will be saved if the algorithm detects any abnormal activity at the ./bcast_ids/forensic directory.
3. Finally, if you want to receive an email when an anomaly is detected, change `SEND_EMAIL` property to `yes` and complete the variables `MAIL_SERVER`, `PORT_MAIL_SERVER`, `SENDER_EMAIL` and `RECEIVERS_EMAIL` on your own. You can check the log file `email_messages.log` in order to visualize if an email was sent well or there was a problem.
