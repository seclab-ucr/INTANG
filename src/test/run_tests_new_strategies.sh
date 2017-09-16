#!/bin/bash

make clean
make
sleep 1

echo "Running test cases with SID 6"
sudo ./test_succ_rate_china.py 6 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with SID 11"
sudo ./test_succ_rate_china.py 11 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with SID 17"
sudo ./test_succ_rate_china.py 17 50
#echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90
#echo "Running test cases with SID 23"
#sudo ./test_succ_rate_china.py 23 50
#echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90
#echo "Running test cases with SID 24"
#sudo ./test_succ_rate_china.py 24 50
#echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90

