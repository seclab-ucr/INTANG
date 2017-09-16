#!/bin/bash

sudo hping3 $1 -p 80 -S -c 1 --ttl $2

