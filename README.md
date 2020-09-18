# BCAST_IDS: A Network Intrusion Detection System with Machine Learning
*Gestión Tributaria Territorial (GTT), Network dept., Alicante (Spain), 2020*
## Abstract
Network intrusion is a growing threat with severe impacts, which can damage in several ways to network infrastructures and digital assets in the well-known cyberspace. A modern technique employed to combat against network intrusion is the development of attack detection systems using Machine Learning and Data Mining. These approaches can help to protect networks because they are able to identify and disconnect malicious network traffic. BCAST_IDS is a Network Intrusion Detection System (NIDS), which attempts to identify unauthorized and anomalous behaviour in a Local Area Network (LAN) looking at the broadcast and unicast traffic. For that, it monitors network activity on one network segment. Then, the system constantly performs analysis and watches for certain traffic patterns. If the detected traffic patterns match the defined policies in the Machine Learning model, a security alert will be generated.

## Description
Machine Learning and Data Mining techniques work by establishing an implicit or explicit model which enables to categorize the analized patterns. Since network intrusion and Malware activities can be considered as anomalies (outliers), BCAST_IDS uses an algorithm, called [**Isolation Forest**](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html), that explicitly identifies them. In principle, outliers are less frequent than regular observations and are different from them in terms of values (they lie further away from the regular observations in the feature space). 

This algorithm is built on the basis of decision trees and the main idea of identifying normal and abnormal activity is in the path length of the tree. A normal point requires more partitions to be identified than abnormal point. 

There are three phases to make this project comes true:
1. **Preprocessing:** feature selection and feature extraction. The data instances that are colleted from the network environment are structured.
2. **Training:** the Machine Learning algorithm is used and extracts patterns from the data collected previously. Then, a system model is built.
3. **Detection:** the monitored traffic data will be used as system input to be compared to the generated system model. If the pattern of the observation is matched with an existing threat, an alarm will be triggered and it will indicate a feasible network intrusion.

The following picture represents an overview of the BCAST_IDS architecture:

![alt text](https://user-images.githubusercontent.com/69505347/91721307-d89dd480-eb98-11ea-9655-6ba4da95e401.png)

### Dataset Generation and Preprocessing
The training dataset can be collected from a real-world connected environment. At this point, the main features have to be identified. There are a whole bunch of features that can be monitored by networking tools for network analysis over the network, but some of them could be redundant. So, we have selected fifteen features and are listed below:

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

Once the features were determined to fed the Isolation Forest algorithm, the next step is to generate the data. This is typically implemented in stages based first on an attack-free netwok and then a number of attacks until all the classes that need to be considered are fully covered by the dataset. The final dataset will cover distinct attack types and attack-free circumstances. 

## Running the BCAST_IDS
### Hardware Prerequisites
Raspberry Pi or PC with Linux (Debian, Ubuntu, CentOS, Fedora...) connected in LAN or any Wifi network.

### Software Prerequisites
You have to install **`Python 3`** (or higher) and the following libraries using the `pip` installer:

```
dpkt psutil numpy pandas sklearn
```
If the Python v3 scripts fail, try to view the location of your Python package installation with the command `which python3` o whichever version you have and then write it in the first line of the Python scripts. Moreover, `git` must be installed in your computer.

### Configuration files
Edit the `config.txt` and fill up the variables on your own. **Time is represented in gregorian calendar**:
```
# POST.SH
## Allow to generate a dataset (enable/disable)
GENERATE_DATASET=enable
FILENAME='dataset'
POST=10
IFACE2=eth1

# BCAST_IDS_LITE
BANANA=MiPC
NET=192.168.0
EXCLUDE_MACS=""
NUM_MACS_TO_ANALIZE=5
## Update time tip.json, tm.json, externos.json, ti6.json, ipf.json
UPDATE_TIME_JSON_HOUR=1800
## Update time ipm.json
UPDATE_TIME_JSON_12HOURS=43200
## Update time tips-week.json
UPDATE_TIME_JSON_WEEK=604800
## Update time tm-month.json
UPDATE_TIME_JSON_MONTH=2592000

## Allow sending emails from BCAST_IDS (enable/disable) 
SEND_EMAIL=disable
MAIL_SERVER=
PORT_MAIL_SERVER=25
SENDER_EMAIL=
RECEIVERS_EMAIL=
```
The meaning of each property is detailed below:

| Variable  | Description |
| ------------- | ------------- |
| `GENERATE_DATASET`  | Allow to generate a dataset (enable/disable). |
| `FILENAME`  | Name of the dataset. |
| `POST`  | Time interval traffic monitoring. |
| `IFACE2`  | Interface where your computer is connected to your network.  |
| `BANANA`  | PC name.  |
| `NET`  | Network range.  |
| `EXCLUDE_MACS`  | MAC addresses to exclude (i.e. the default gateway). If there are two or more, they should separate by ',' i.e. MAC1,MAC2 |
| `NUM_MACS_TO_ANALIZE`  | Number of MACs to predict their activities. Three possible values: **number**, **'auto'** (it takes the first 20% top activity MACs) and **'none'** (the Machine Learning algorithm analyze all MACs seen in each network capture). |
| `UPDATE_TIME_JSON_HOUR`  | Time to update tip.json, tm.json, externos.json, ti6.json, ipf.json. |
| `UPDATE_TIME_JSON_12HOURS`  | Time to update ipm.json. |
| `UPDATE_TIME_JSON_WEEK`  | Time to update tips-week.json. |
| `UPDATE_TIME_JSON_MONTH`  | Time to update tm-month.json. |
| `SEND_EMAIL`  | Enable or disable to send emails. |
| `MAIL_SERVER`  | Mail server name. |
| `PORT_MAIL_SERVER`  | Port mail server. |
| `SENDER_EMAIL`  | Sender email. |
| `RECEIVERS_EMAIL`  | Receivers mail. If there are two or more, they should separate by ',' i.e. mail1@tesbcast.com,mail2@tesbcast.com.  |

### Run the Project

#### Download

```
git clone https://github.com/redesgtt/bcast_ids.git

```

#### Preprocessing
1. Open the bcast_ids folder and execute `./post.sh` at the command prompt. If you want to run it at the background you can type `./post.sh &`. IMPORTANT: Make sure you are in a 'root' user.
2. The dataset is now generating. Type `tail -f dataset.csv` at the command prompt to observe it. 
3. It is time to make some kind of cyberattacks. If you are in a Wifi network, try to download any network scanning tool in order to make outliers in the data. There are plenty of them in the App Store (iOs) or Play Store (Android), i.e. [Net Analyzer](https://play.google.com/store/apps/details?id=net.techet.netanalyzerlite.an&hl=es_419). You can perform cyberattacks with `nmap, arp-scan, netdiscover...` using a computer too. Make sure that this computer and BCAST_IDS are connected in the same network.
4. Observe the data which is generated in the `dataset.csv`. Combine normal and abnormal entries. It is highly recommended that the file has 10.000-12.000 lines.
6. At the same time, you can also see the .json files. Their time expiration can be modified in config.txt file through `UPDATE_TIME_JSON_HOUR`, `UPDATE_TIME_JSON_12HOURS`, `UPDATE_TIME_JSON_WEEK` and `UPDATE_TIME_JSON_MONTH` properties:

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

5. Then, in order to train the Isolation Forest algorithm (next step), you can stop the `./post.sh` executable.

#### Training
1. Firstly, use the script `./train_iso_forest.py` to extract patterns from the data collected in the file `dataset.csv`. Feel free to change the contamination parameter `-c`, that is the proportion of outliers in the dataset. Remember that this value must be between 0 and 0.5. Analyze the outliers given by the algorithm.
2. Soon afterward, a model will be generated with the name `model_iso_forest.bin`.
3. Make some tests with the script `./predict_iso_forest.py` and verify the effectiveness of the Isolation Forest algorithm.

#### Detection
1. Execute again `./post.sh`. Now, the BCAST_IDS should be running perfectly on your computer or RaspberryPi and detect anomalies in your network! If the algorithm detects any abnormal activity, it will be registered at `macs_abnormal_act.log`. Moreover if the system detects a new MAC in the network, it will be registered at `new_macs_detected.log`
2. Finally, if you want to receive an email when an anomaly is detected, change `SEND_EMAIL` property to `enable` and complete the variables `MAIL_SERVER`, `PORT_MAIL_SERVER`, `SENDER_EMAIL` and `RECEIVERS_EMAIL` on your own.
