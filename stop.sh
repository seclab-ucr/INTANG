#!/bin/bash

PID=`pidof intangd`
if [ -z $PID ]; then
    echo "No daemon running."
    exit -1
fi

sudo kill -INT $PID && echo "Daemon exited."

