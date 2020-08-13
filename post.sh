#!/bin/bash
. ./config.txt

echo "-Z root -w ./round_time%S.cap -G $POST -z ./bcast_AI_v15.py >> $FILENAME.csv"

tcpdump -ni $IFACE2  -Z root -w ./round_time%S.cap -G $POST -z ./integrate-bcast_AI_v22.py >> $FILENAME.csv
