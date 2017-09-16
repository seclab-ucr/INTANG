#!/bin/bash

make clean
make
sleep 1

#echo "Running test cases with Strategy dummy(0)"
#sudo ./test_succ_rate_new.py 0 50
echo "Running test cases with Strategy rst_super(6)"
sudo ./test_succ_rate_new.py 6 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy data_overlapping_combined(10)"
sudo ./test_succ_rate_cn.py 10 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy multiple_syn(11)"
sudo ./test_succ_rate_cn.py 11 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy reverse_tcb(17)"
sudo ./test_succ_rate_cn.py 17 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy rst_organic(19)"
sudo ./test_succ_rate_cn.py 19 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy data_overlapping_organic(20)"
sudo ./test_succ_rate_cn.py 20 50
echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90
#echo "Running test cases with Strategy data_overlapping_organic_wrong_checksum(21)"
#sudo ./test_succ_rate_cn.py 21 50
#echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90
#echo "Running test cases with Strategy data_overlapping_combined_wrong_checksum(22)"
#sudo ./test_succ_rate_cn.py 22 50
#echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90
#echo "Running test cases with Strategy multiple_syn_wrong_checksum(23)"
#sudo ./test_succ_rate_cn.py 23 50
#echo "Now sleep for 90 seconds and then will start the next test."
#sleep 90
#echo "Running test cases with Strategy reverse_tcb_wrong_checksum(24)"
#sudo ./test_succ_rate_cn.py 24 50

