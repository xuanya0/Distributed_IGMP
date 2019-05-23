#!/bin/sh


echo "tunneling interface pairs setup s1-s4------------------------------------"
ip addr add 10.0.1.2/24 dev s1-eth1
#ip route replace 10.0.1.0/24 via 10.0.1.1
#ip addr add 10.0.1.1/24 dev s4-eth3
#ip route add 10.0.0.0/16 dev s1-eth1

echo "tunneling interface pairs setup s2-s5------------------------------------"
ip addr add 10.0.2.2/24 dev s2-eth1
#ip addr add 10.0.2.1/24 dev s5-eth3
#ip route add 10.0.0.0/16 via 10.0.2.1

echo "tunneling interface pairs setup s3-s6------------------------------------"
ip addr add 10.0.3.2/24 dev s3-eth1


tunneling_type="vxlan"

echo "setting up tunneling interfaces btw s1_s2 -------------------------------------"
ovs-vsctl add-port s1 tun1_2 -- set interface tun1_2 type=$tunneling_type \
options:local_ip=10.0.1.2 options:remote_ip=10.0.2.2 options:key=flow

ovs-vsctl add-port s2 tun2_1 -- set interface tun2_1 type=$tunneling_type \
options:local_ip=10.0.2.2 options:remote_ip=10.0.1.2 options:key=flow

echo "setting up tunneling interfaces btw s1_s3 -------------------------------------"
ovs-vsctl add-port s1 tun1_3 -- set interface tun1_3 type=$tunneling_type \
options:local_ip=10.0.1.2 options:remote_ip=10.0.3.2 options:key=flow

ovs-vsctl add-port s3 tun3_1 -- set interface tun3_1 type=$tunneling_type \
options:local_ip=10.0.3.2 options:remote_ip=10.0.1.2 options:key=flow


echo "setting up tunneling interfaces btw s2_s3 -------------------------------------"
ovs-vsctl add-port s2 tun2_3 -- set interface tun2_3 type=$tunneling_type \
options:local_ip=10.0.2.2 options:remote_ip=10.0.3.2 options:key=flow

ovs-vsctl add-port s3 tun3_2 -- set interface tun3_2 type=$tunneling_type \
options:local_ip=10.0.3.2 options:remote_ip=10.0.2.2 options:key=flow
