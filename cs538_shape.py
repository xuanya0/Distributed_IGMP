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
    h1 = net.addHost('h1', cls=Host, ip='172.16.0.1/24', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='172.16.0.2/24', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='172.16.0.3/24', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='172.16.0.4/24', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='172.16.0.5/24', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='172.16.0.6/24', defaultRoute=None)

    info( '*** Add links\n')
    
    net.addLink(s4, s5)
    net.addLink(s5, s6)
    net.addLink(s6, s4)

    net.addLink(s1, s4)
    net.addLink(s2, s5)
    net.addLink(s3, s6)
        
    net.addLink(s1, h1)
    net.addLink(s1, h2)

    net.addLink(s2, h3)
    net.addLink(s2, h4)

    net.addLink(s3, h5)
    net.addLink(s3, h6)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s4').start([routers])
    net.get('s2').start([gateways])
    net.get('s5').start([routers])
    net.get('s6').start([routers])
    net.get('s3').start([gateways])
    net.get('s1').start([gateways])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

