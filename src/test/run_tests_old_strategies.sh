#!/bin/bash

make clean
make
sleep 1

echo "Running test cases with SID 19"
sudo ./test_succ_rate_china.py 19 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with SID 20"
sudo ./test_succ_rate_china.py 20 50

