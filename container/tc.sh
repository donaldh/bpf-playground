#!/bin/sh

tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf da obj tc_svc.o sec tc
