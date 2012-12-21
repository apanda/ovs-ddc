#!/bin/bash
service openvswitch-switch stop
rmmod openvswitch
sleep 1
insmod datapath/linux/openvswitch.ko
service openvswitch-switch  start
