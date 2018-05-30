#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='172.16.0.0/16')

    info( '*** Adding controller\n' )
    gateways=net.addController(name='gateways',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    routers=net.addController(name='routers',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)



    info( '*** Add switches\n')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h11 = net.addHost('h11', cls=Host, ip='172.16.1.2/24', defaultRoute='via 172.16.1.1')
    h12 = net.addHost('h12', cls=Host, ip='172.16.1.3/24', defaultRoute='via 172.16.1.1')
    h13 = net.addHost('h13', cls=Host, ip='172.16.1.4/24', defaultRoute='via 172.16.1.1')

    h21 = net.addHost('h21', cls=Host, ip='172.16.2.2/24', defaultRoute='via 172.16.2.1')
    h22 = net.addHost('h22', cls=Host, ip='172.16.2.3/24', defaultRoute='via 172.16.2.1')
    h23 = net.addHost('h23', cls=Host, ip='172.16.2.4/24', defaultRoute='via 172.16.2.1')

    h31 = net.addHost('h31', cls=Host, ip='172.16.3.2/24', defaultRoute='via 172.16.3.1')
    h32 = net.addHost('h32', cls=Host, ip='172.16.3.3/24', defaultRoute='via 172.16.3.1')
    h33 = net.addHost('h33', cls=Host, ip='172.16.3.4/24', defaultRoute='via 172.16.3.1')

    info( '*** Add links\n')
    
    # build the ring for core network
    net.addLink(s4, s5)
    net.addLink(s5, s6)
    net.addLink(s6, s4)

    # build links to edge routers
    net.addLink(s1, s4)
    net.addLink(s2, s5)
    net.addLink(s3, s6)

    # s1 hosts
    net.addLink(s1, h11)
    net.addLink(s1, h12)
    net.addLink(s1, h13)

    # s2 hosts
    net.addLink(s2, h21)
    net.addLink(s2, h22)
    net.addLink(s2, h23)

    # s3 hosts
    net.addLink(s3, h31)
    net.addLink(s3, h32)
    net.addLink(s3, h33)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s4').start([]) #([routers])
    net.get('s2').start([gateways])
    net.get('s5').start([]) #([routers])
    net.get('s6').start([]) #([routers])
    net.get('s3').start([gateways])
    net.get('s1').start([gateways])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

