#!/bin/bash

if [ -z $1 ] || [ -z $2 ]; then
    echo "$0 <server> <sid>"
    exit 0
fi

#SERVER_IP="97.90.194.165"
SERVER_IP=$1
SID=$2

./run.sh $SID
sleep 2
#wget --timeout=1 --tries=1 http://$SERVER_IP/?keyword=goodword -O-
./probe.py $SERVER_IP $SERVER_IP
./stop.sh

