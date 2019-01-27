#!/bin/bash
# A test script.

for i in `seq 1 10`;
do
    openssl s_client -connect 192.168.178.30:4710 &
done
sleep 10
