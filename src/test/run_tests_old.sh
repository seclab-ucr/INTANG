#!/bin/bash

make clean
make
sleep 1

#echo "Running test cases with Strategy dummy(0)"
#sudo ./test_succ_rate_new.py 0 50
echo "Running test cases with Strategy old_fake_syn_ttl(26)"
sudo ./test_succ_rate_new.py 26 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_fake_syn_wrong_checksum(27)"
sudo ./test_succ_rate_new.py 27 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_ooo_ip_fragment(28)"
sudo ./test_succ_rate_new.py 28 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_ooo_tcp_fragment(29)"
sudo ./test_succ_rate_new.py 29 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_io_ttl(30)"
sudo ./test_succ_rate_new.py 30 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_io_wrong_ack(31)"
sudo ./test_succ_rate_new.py 31 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_io_wrong_checksum(32)"
sudo ./test_succ_rate_new.py 32 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_io_no_ack_flag(33)"
sudo ./test_succ_rate_new.py 33 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_rst_ttl(34)"
sudo ./test_succ_rate_new.py 34 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_rst_wrong_checksum(35)"
sudo ./test_succ_rate_new.py 35 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_rst_wrong_seq(36)"
sudo ./test_succ_rate_new.py 36 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_rst_ack_ttl(37)"
sudo ./test_succ_rate_new.py 37 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_rst_ack_wrong_checksum(38)"
sudo ./test_succ_rate_new.py 38 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_rst_ack_wrong_seq(39)"
sudo ./test_succ_rate_new.py 39 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_fin_ttl(40)"
sudo ./test_succ_rate_new.py 40 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_fin_wrong_checksum(41)"
sudo ./test_succ_rate_new.py 41 50
echo "Now sleep for 90 seconds and then will start the next test."
sleep 90
echo "Running test cases with Strategy old_fin_wrong_seq(42)"
sudo ./test_succ_rate_new.py 42 50
echo "Now sleep for 90 seconds and then will start the next test."


