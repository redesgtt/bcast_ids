#!/bin/bash
. ./config.txt

MAC=`/sbin/ifconfig $IFACE2 | grep ether | awk '{print $2}'`

echo "tcpdump -ni $IFACE2  -Z root -w ./round_time%S.cap -G $POST -z ./bcast_ids_lite_v2.py not ether host $MAC >> $FILENAME.csv"

tcpdump -ni $IFACE2  -Z root -w ./round_time%S.cap -G $POST -z ./bcast_ids_lite_v2.py "not ether host $MAC" >> $FILENAME.csv
