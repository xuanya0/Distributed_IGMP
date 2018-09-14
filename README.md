# Distributed_IGMP

A project to enable inter-LAN communication for Real-Time Publish-Subscribe protocol. 
The MPLS branch provides a layer-3 tunneling to correctly route traffic to desired listeners.




## Getting Started

### Prerequisites
Ryu-controller, Open vSwitch, Mininet

## Running the Simulation
### Orchestrating the Topology

Execute the script below
```
cs538_shape.py
```
This gives you a topology as follows:
![Topo](https://github.com/xzhng120/Distributed_IGMP/blob/mpls/docs/sdn_topo.PNG)
It's optional to have a Ryu controller for routers as they can have static routes.

### Static MPLS Routes for Routers in the Middle

This script installs static routes for subnets s1, s2, s3 and set interface properties. The label IDs are simply their digits (could be a violation of MPLS reserved label IDs).
```
if_conf.sh
```

### Starting the Ryu Controller: 
```
ryu-manager --ofp-tcp-listen-port 6633 gateways.py
```
Or run
```
gateways.sh
```

### Testing
Running the following command on mininet CLI starts an xterm for host X. On the xterm, you can run multicast applications to test the topology and correctness of the controller
```
xterm hX
```

Multicast traffic should be able to cross any boundary without issues. Testing was conducted with RTI Perf Test
https://github.com/rticommunity/rtiperftest

## REST API
A few security mechanisms were implemented in the controller to cut off a specific LAN or host. Documentation to be expanded...

## Control Plane Logic
This design strives to make IP multicast possible across LANs possible by querying with IGMPv2 messages and capturing responses/requests.
see [lib/igmplib.py](https://github.com/xzhng120/Distributed_IGMP/blob/mpls/lib/igmplib.py) for details
![Topo](https://github.com/xzhng120/Distributed_IGMP/blob/mpls/docs/control_plane.png)
