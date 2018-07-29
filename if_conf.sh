#!/bin/sh


########## IMPORTANT #########
# check MTU at hosts to avoid fragmentation, negatively effects (recommended mtu==1400)'
ifconfig s1-eth1 mtu 1600
ifconfig s2-eth1 mtu 1600
ifconfig s3-eth1 mtu 1600
ifconfig s4-eth1 mtu 1600
ifconfig s4-eth2 mtu 1600
ifconfig s4-eth3 mtu 1600
ifconfig s5-eth1 mtu 1600
ifconfig s5-eth2 mtu 1600
ifconfig s5-eth3 mtu 1600
ifconfig s6-eth1 mtu 1600
ifconfig s6-eth2 mtu 1600
ifconfig s6-eth3 mtu 1600


# disable flooding on northbound interfaces
ovs-ofctl mod-port s1 1 no-flood
ovs-ofctl mod-port s2 1 no-flood
ovs-ofctl mod-port s3 1 no-flood

# static routing, assuming unicast for now
ovs-ofctl add-flow s4 dl_type=0x8847,mpls_label=1,actions=output:3
ovs-ofctl add-flow s4 dl_type=0x8847,mpls_label=2,actions=output:1
ovs-ofctl add-flow s4 dl_type=0x8847,mpls_label=3,actions=output:2
ovs-ofctl add-flow s4 actions=

ovs-ofctl add-flow s5 dl_type=0x8847,mpls_label=1,actions=output:1
ovs-ofctl add-flow s5 dl_type=0x8847,mpls_label=2,actions=output:3
ovs-ofctl add-flow s5 dl_type=0x8847,mpls_label=3,actions=output:2
ovs-ofctl add-flow s5 actions=

ovs-ofctl add-flow s6 dl_type=0x8847,mpls_label=1,actions=output:2
ovs-ofctl add-flow s6 dl_type=0x8847,mpls_label=2,actions=output:1
ovs-ofctl add-flow s6 dl_type=0x8847,mpls_label=3,actions=output:3
ovs-ofctl add-flow s6 actions=