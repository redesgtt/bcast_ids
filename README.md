# BCAST_IDS: A Network Intrusion Detection System with Machine Learning
*Gestión Tributaria Territorial (GTT), Network dept., Alicante (Spain), 2020*

## Table of Contents  
   * [Abstract](#abstract)
   * [Description](#description)
      * [Architecture at a glance](#architecture-at-a-glance)
      * [Dataset Generation](#dataset-generation)
   * [Running the BCAST_IDS](#running-the-bcast_ids)
      * [Hardware Prerequisites](#hardware-prerequisites)
      * [Software Prerequisites](#software-prerequisites)
      * [Configuration file](#configuration-file)
      * [Run the Project](#run-the-project)
        * [Download](#download)
        * [Preprocessing](#preprocessing)
        * [Training](#training)
          * [Automated training](#automated-training)
          * [Manual training](#manual-training)
        * [Detection](#detection)
        * [Dealing with false positives](#dealing-with-false-positives)
   * [References](#references)

## Abstract
Network intrusion is a growing threat with severe impacts, which can damage in several ways to network infrastructures and digital assets in the well-known cyberspace. We all know Local Area Network (LAN) is a collection of locally connected PC which share information over the private network. If one  PC gets infected with Malware or Adware species, then the entire connected PC on the same LAN network will also catch the same infection. A modern approach employed to combat against network intrusion is the development of attack detection systems using Machine Learning and Data Mining techniques. These approaches can help to protect networks because they are able to identify malicious network traffic. BCAST_IDS is a Network Intrusion Detection System (NIDS), which attempts to identify unauthorized and anomalous behaviour in a LAN looking at the broadcast and unicast traffic. For that, it monitors network activity on one network segment. Then, the system constantly performs analysis and watches for certain traffic patterns. If the detected traffic pattern match the defined policies in the Machine Learning model, a security alert will be generated.

## Description
Machine Learning and Data Mining techniques work by establishing an implicit or explicit model which enables to categorize data patterns. Since network intrusion and Malware activities can be considered as anomalies (outliers), BCAST_IDS uses an unsupervised Machine Learning algorithm, called [**Isolation Forest**](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html), that explicitly identifies them. In principle, outliers are less frequent than regular observations and are different from them in terms of values (they lie further away from the regular observations in the feature space). 

The aforementioned algorithm is built on the basis of [decision trees](https://scikit-learn.org/stable/modules/tree.html) and the main idea of identifying normal and abnormal activity is in the path length of the tree. A normal point requires more partitions to be identified than abnormal point.

There are three main phases to make this project comes true:
1. **Preprocessing:** feature selection and feature extraction. Data instances that are colleted from the network environment are structured.
2. **Training:** a Machine Learning algorithm is used to extract patterns from the data collected previously. Then, a system model is built.
3. **Detection:** the monitored traffic data will be used as system input to be compared to the generated system model. If the pattern of the observation is matched with a potential threat, an alarm will be triggered and it will indicate a feasible network intrusion.

### Architecture at a glance
The following picture represents an overview of the BCAST_IDS architecture:

![alt text](https://user-images.githubusercontent.com/69505347/100358073-e75c2200-2ff5-11eb-829d-a3e66906109b.png)

The system will also generate the following files:
- **JSON files (time is represented as a integer number expressed in seconds since the epoch, in UTC)**

| File name  | Description |
| ------------- | ------------- |
| **tip.json**  | {IP source subnet:time}. Active source IPs (v.4) which belong to the network range specified in the `NET` attribute of the config file |
| **tm.json**  | {MAC source:time}. Active source MACs  |
| **externos.json**  | {IP source:time}. Active source IPs which do not belong to the network range specified in the `NET` attribute of the config file  |
| **ti6.json**  | {MAC source:time}. Active source IPs (v.6) |
| **ipf.json**  | {IP source_IP destination:time}. ARP trafic generated between two existing IPs which belong to the network range specified in the `NET` attribute of the config file |
| **ipm.json**  |  {MAC source:IP source}. Active source MACs and IPs which have generated ARP traffic in the network range specified in the config file |
| **tips-week.json**  | {IP source:time}. Active source IPs (v.4) which belong to the network range specified in the `NET` attribute of the config file. It has a week expiration by default |
| **tm-month.json**  | {MAC source:time}. Active source MACs which have a month expiration by default |

- **LOG files**

| File name  | Description |
| ------------- | ------------- |
| **macs_abnormal_act.log**  | It indicates the MACs that the algorithm has detected as abnormal |
| **messages_training.log**  | It indicates if the automated training of the algorithm was okay or not  |
| **telegram_messages.log**  | File that records the messages sended using Telegram |
| **email_messages.log**  | It indicates if the email was sent correctly or not |

- **PCAP files**

| File name  | Description |
| ------------- | ------------- |
| **round{num}.cap**  | Packet data in a cycled files obtained by tcpdump, which is a data-network packet analyzer computer program  |
| **./bcast_ids/forensic/{MAC}/{date}.cap**  | It contains the network capture of the suspicious traffic that the algorithm has identified as malicious |


- **TMP files**

| File name  | Description |
| ------------- | ------------- |
| **time.tmp**  | Temporary file that BCAST_IDS uses in order to make the automated training  |

### Dataset Generation
The training dataset is collected from a real-world connected environment. At this point, the main features have to be identified. There are a whole bunch of features that can be monitored by networking tools for network analysis over the network, but some of them could be redundant. So, we have selected nineteen features and are listed below:

| Feature  | Description |
| ------------- | ------------- |
| MAC  | MAC address  |
| num_MAC  | Total network packets generated from a specific MAC address |
| UCAST  | Total UNICAST traffic generated from a specific MAC address |
| MCAST  | Total MULTICAST traffic generated from a specific MAC address  |
| BCAST  | Total BROADCAST traffic generated from a specific MAC address  |
| ARP  | Total ARP Request, ARP Probe, ARP Announcement and ARP Gratitous traffic generated from a specific MAC address  |
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

Once the features were determined to fed the Isolation Forest algorithm later on, the next step is to generate the data. This is typically implemented in stages based first on an attack-free netwok and then a number of attacks until all the classes that need to be considered are fully covered by the dataset. The final dataset should cover distinct attack types and attack-free circumstances. 

## Running the BCAST_IDS
### Hardware Prerequisites
PC with Linux (Debian, Ubuntu, CentOS, Fedora...) connected in LAN or any Wifi network. 

### Software Prerequisites
BCAST_IDS requires **`Python 3` branch** and the additional libraries listed below:
```
dpkt psutil numpy pandas sklearn
```

### Configuration file
You can modify the `config.txt` file and fill up the variables on your own:
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
NET=192.168
EXCLUDE_MACS=
## Update time tip.json, tm.json, externos.json, ti6.json, ipf.json (in seconds)
UPDATE_TIME_JSON_HOUR=3600
## Update time ipm.json (in seconds)
UPDATE_TIME_JSON_12HOURS=43200
## Update time tips-week.json (in seconds)
UPDATE_TIME_JSON_WEEK=604800
## Update time tm-month.json (in seconds)
UPDATE_TIME_JSON_MONTH=2592000
## Enable auto-training (yes/no)
AUTOMATED_TRAINING=yes
## Time to automate training (in seconds)
TIME_AUTOMATED_TRAINING=7200
## Enable to generate outliers
GENERATE_OUTLIERS=yes
## Percentaje of the outliers in the data (auto, float number: 0 < CONTAMINATION < 0.5)
CONTAMINATION=auto

## Allow sending emails from BCAST_IDS (yes/no)
SEND_EMAIL=no
MAIL_SERVER=
PORT_MAIL_SERVER=
SENDER_EMAIL=
### In case you need to type a password to send emails (plain text)
SENDER_PASSWORD=
RECEIVERS_EMAIL=

## Allow to send alerts with Telegram
TELEGRAM_INTEGRATION=no
BOT_TELEGRAM_TOKEN=
CHAT_ID=
```
The meaning of each variable is detailed below:

| Variable  | Description |
| ------------- | ------------- |
| `GENERATE_DATASET`  | Allow to generate a dataset (yes/no) |
| `FILENAME`  | Name of the dataset. Its name is 'dataset' by default |
| `POST`  | Time interval traffic monitoring |
| `IFACE2`  | Interface where your computer is connected to your network  |
| `NET`  | Network range |
| `EXCLUDE_MACS`  | MAC addresses to exclude (i.e. the default gateway). If there are two or more, they should separate by ',' i.e. EXCLUDE_MACS=000fxxxx,5f089xxxx |
| `UPDATE_TIME_JSON_HOUR`  | Time to update tip.json, tm.json, externos.json, ti6.json, ipf.json |
| `UPDATE_TIME_JSON_12HOURS`  | Time to update ipm.json |
| `UPDATE_TIME_JSON_WEEK`  | Time to update tips-week.json |
| `UPDATE_TIME_JSON_MONTH`  | Time to update tm-month.json |
| `GENERATE_LOG_FILES`  | Enable to generate log files (email_messages.log, macs_abnormal_act.log, messages_training.log, new_macs_detected.log) |
| `AUTOMATED_TRAINING`  | In order to train the algorithm automatically (yes/no) |
| `TIME_AUTOMATED_TRAINING`  | Countdown to train the algorithm with the training dataset and generate the model automatically. It is 7200 seconds by default |
| `CONTAMINATION`  | It specifies the percentage of observations we believe to be outliers. It can be two different values: 'auto' or a float number.  If it is set to 'auto', contamination is equal to the number of ARP_noIP columns largest than 40 (its value is large in network scanning attacks) divided by total rows in the dataset at the time of automated trainning. If it is a number, the parameter must be between 0.0 and 0.5 |
| `SEND_EMAIL`  | Enable or disable to send emails |
| `MAIL_SERVER`  | Mail server name |
| `PORT_MAIL_SERVER`  | Port mail server |
| `SENDER_EMAIL`  | Sender email |
| `SENDER_PASSWORD`  | Sender password. If you are using TLS/STARTTLS port, you probably have to fill up this |
| `RECEIVERS_EMAIL`  | Receivers mail. If there are two or more, they should separate by ',' i.e. RECEIVERS_EMAIL=mail1@tesbcast.com,mail2@tesbcast.com.  |
| `TELEGRAM_INTEGRATION`  | Enable or disable to send messages through a Telegram bot |
| `BOT_TELEGRAM_TOKEN`  | API Key of the Telegram BOT |
| `CHAT_ID`  | User identifier to send messages when anomaly is detected  |

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
1. Firstly, **make sure you are as a 'root' user** and you fill up correctly the variables of config.txt file (`IFACE2`, `NET`, `EXCLUDE_MACS`...). Execute `./post.sh` in order to generate training data. Remember that in this phase the variable `GENERATE_DATASET` should set to 'yes'. Keep this script running. If you want to run it at the background you can type `./post.sh &` at the command prompt. Network traffic is analized each 10 seconds by default (`POST` variable).
2. The training dataset is now generating and is growing over each `POST` seconds (10 seconds by default). Type `tail -f dataset.csv` at the command prompt to observe it.
3. If you have set the varible `GENERATE_OUTLIERS` to 'yes', the system will make outliers for you with abnormal data patterns, which can be considered as malicious.
4. If the variable `GENERATE_OUTLIERS` is set to 'no', you have to make **cyberattacks on your own network**. If you are in a Wifi network, try to download any **network scanning tool in order to make outliers in the data** for example. For that, you can use your smartphone or tablet. There are plenty of them in the App Store (iOs) or Play Store (Android), i.e. [Net Analyzer](https://play.google.com/store/apps/details?id=net.techet.netanalyzerlite.an&hl=es_419). If want to use a distinct PC computer to perform cyberattacks, you can employ `nmap, arp-scan, netdiscover...` or any network scanning tool you know. Make sure that the devices your perform the cyberattacks and BCAST_IDS are connected in the same network. 
5. Observe the data which is generated in the `dataset.csv`. Combine normal and abnormal entries. It is highly recommended that the training dataset has between 12.000-25.000 lines.
6. You can also make outliers manually by executing `./generate_outliers.py` and append them in the training dataset.
7. At the same time you can also see the .json files. Remember that their time expiration can be modified in config.txt file through `UPDATE_TIME_JSON_HOUR`, `UPDATE_TIME_JSON_12HOURS`, `UPDATE_TIME_JSON_WEEK` and `UPDATE_TIME_JSON_MONTH` properties.

#### Training
##### Automated training
1. If there is no a Machine Learning model in the bcast_ids directory, the system can extract data patterns automatically from the data collected in `dataset.csv` so far bear in mind the countdown specified in `TIME_AUTOMATED_TRAINING`. Also, make sure `AUTOMATED_TRAINING` is set to 'yes'. Remember you can adjust the contamination parameter of the Isolation Forest algorithm in the config file (it is set to 'auto' by default).
2. Once the countdown is over and if everything went as expected, a model will be created in the bcast_ids folder with the name `model_iso_forest.bin` and the results could be checked at the file `training_messages.log`. Otherwise, an message error will appear at the aforementioned log file.
3. Additionally, you can use the notebook `Notebook - BCAST_IDS Lite Version.ipynb` in order to perform some visualizations of the data you are collected and the abnormal points in a three-dimensional space. 

##### Manual training
1. You can use the script `./train_iso_forest.py` manually to extract patterns from the data collected in the file `dataset.csv`. Feel free to change the contamination parameter `-c`, that is the proportion of outliers in the dataset. Note that this value must be between 0 and 0.5. Analyze the outliers given by the algorithm (they will pop up at the screen after executing the training script).
2. Soon afterward, a model will be generated with the name `model_iso_forest.bin`. Note that this model is located in the main project directory:  `./bcast_ids/model_iso_forest.bin`.
3. Make some tests with the script `./predict_iso_forest.py` and verify the effectiveness of the Isolation Forest algorithm.
4. You can use the notebook `Notebook - BCAST_IDS Lite Version.ipynb` in order to perform some visualizations of the data you are collected and the abnormal points in a three-dimensional space. 

#### Detection
**BCAST_IDS could detect anomalous network behaviour in two different ways:**
1. **By the Machine Learning algorithm**. If the model has saved successfully and you have checked that the outliers detected by the algorithm are appropiate in the training phase, BCAST_IDS should predict anomalies on your network using the monitoring data each `POST` seconds! If you wish, you can set `GENERATE_DATASET` to 'no' because we do not need saving the data in a file (the model was generated in the previous phase). It is up to you! So, if the algorithm detects any abnormal activity, it will be registered at `macs_abnormal_act.log`.
2. **By network packet patterns.** A MAC address, which are not included in EXCLUDE_MACS property of the config.txt file,  has asked for the MAC of the computer where is installed the BCAST_IDS, using ARP, IPv4 or IPv6 protocols. Furthermore, as long as the computer where is installed the BCAST_IDs generates ICMPv6 Parameter Problem messages (abnormal behaviour), the system will detect it as well.

If the program detects any of the two previous circumstances, a network capture (.pcap file) will be saved in the `./bcast_ids/forensic` directory.

If you want to receive an email when an anomaly is detected, change `SEND_EMAIL` property to `yes` and fill up the variables `MAIL_SERVER`, `PORT_MAIL_SERVER`, `SENDER_EMAIL` and `RECEIVERS_EMAIL` on your own. You can check the log file `email_messages.log` in order to visualize if an email was sent successfully or not. Moreover, you can execute the script `./send_email.py` to check if you have configured the email properties of the config file (`MAIL_SERVER`, `PORT_MAIL_SERVER`, `SENDER_EMAIL` and `RECEIVERS_EMAIL`) successfully and send a test message.

Last but not least, if you want to receive an alert when an anomaly is detected through **Telegram**, you have to follow these steps:
   - Make sure you have the Telegram app downloaded on your smartphone and you are able to send and receive messages using this application.
   - Next, you need to make a bot, which is a third-party application that runs inside Telegram. In our case, the bot will be the sender of the message you receive when an anomaly is detected in the network. You can create a bot by talking to [BotFather](https://core.telegram.org/bots), which is a Telegram bot which allows to create and manage your own Telegram bots. 
   - You can type the /help command in Telegram to view all the possibilities which you can do with BotFather. Since it is required to create a bot, write “/newbot” and follow the instructions that BotFather tells you.   
   - Once you received your authorization token, paste it into the `BOT_TELEGRAM_TOKEN` property of the config.txt file.
   - After that, search in the Telegram search bar the bot you have just created. Click it and press /start. After this, the bot will capture your chat_id, that is, a unique and invariable identifier that Telegram has assigned you to maintain permanent communication with the bot.   
   - Then, execute the script `./telegram_integration.py -i` to obtain your chat_id.
   - You can try to send a message using the option `./telegram_integration -t [CHAT_ID]` and see if you receive an alert from your bot like this: *“Congrats! You have configured successfully the integration with Telegram!”*
   - Finally, you have to copy your chat_id and paste it into the `CHAT_ID` property and set the `TELEGRAM_INTEGRATION` to `yes` in the config.txt. At this time, the system will send an alert when an anomaly is detected to your Telegram account using the bot you have created. The log results will be registered at `telegram_messages.log`.

#### Dealing with false positives
If you observe that the BCAST_iDS generates lots of false positives in the prediction through the Isolation Forest algorithm, you can readjust the model using the script  `./train_iso_forest.py`. As we explained above, this script extracts abnormal patterns from the data collected in the file `dataset.csv`. Feel free to change the contamination parameter `-c`, which is the proportion of outliers in the dataset. Note that this value must be between 0 and 0.5. Then, analyze the outliers given by the algorithm (they will pop up at the screen after executing the training script). Afterwards, a model will be generated with the name `model_iso_forest.bin` in the main project directory. Make some tests with the script `./predict_iso_forest.py` in order to verify the effectiveness of the Isolation Forest algorithm and make sure that there are less false positives than before.

## References
1. Buczak AL, Guven E (2016) A survey of data mining and machine learning methods for cyber security intrusion detection. IEEE Commun Surv Tutor 18(2):1153–1176. https://doi.org/10.1109/COMST.2015.2494502
2. Sommer R, Paxson V (2010) Outside the closed world: on using machine learning for network intrusion detection. In: Proceedings of the 2010 IEEE Symposium on Security and Privacy. IEEE Computer Society, Los Alamitos, CA, USA, pp 305–316. https://doi.org/10.1109/SP.2010.25
3. Russell SJ, Norvig P (2009) Artificial intelligence: a modern approach, 3rd edn. Pearson, Essex
4. Farnaaz N, Jabbar M (2016) Random forest modeling for network intrusion detection system. Procedia Comput Sci 89:213–217. https://doi.org/10.1016/j.procs.2016.06.047
5. Garfinkel S (2002) Network forensics: tapping the Internet. https://paulohm.com/classes/cc06/files/Week6%20Network%20Forensics.pdf 
6. Moradi M, Zulkernine M (2004) A neural network based system for intrusion detection and classification of attacks. http://research.cs.queensu.ca/~moradi/148-04-MM-MZ.pdf
