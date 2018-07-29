#!/usr/bin/python

"""
This example shows how to add an interface (for example a real
hardware interface) to a network after the network is created.
"""

import re
import sys
import os

from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.topolib import TreeTopo
from mininet.util import quietRun

def checkIntf( intf ):
    "Make sure intf exists and is not configured."
    config = quietRun( 'ifconfig %s 2>/dev/null' % intf, shell=True )
    if not config:
        error( 'Error:', intf, 'does not exist!\n' )
        exit( 1 )
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', config )
    if ips:
        error( 'Error:', intf, 'has an IP address,'
               'and is probably in use!\n' )
        exit( 1 )

if __name__ == '__main__':

    # debug levels
    # debug info output warning error critical
    setLogLevel( 'debug' )

    ifs = [] # ['eth1','eth2']

    # try to get hw intf from the command line; by default, use eth1
    # intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    info( '*** Connecting to hw intf: %s' % ifs )

    info( '*** Checking', ifs, '\n' )
    for interface in ifs:
        checkIntf( interface )

    info( '*** Creating network\n' )
    net = Mininet( topo=TreeTopo( depth=1, fanout=4 ) )


    switch = net.switches[ 0 ]


    info( '*** Adding hardware interface', ifs, 'to switch',
          switch.name, '\n' )
    for interface in ifs:
        _intf = Intf( interface, node=switch )




    for ind, host in enumerate(net.hosts,1):
        host.setIP('10.0.99.%d ' % ind, 8)
    info( '*** Note: you may need to reconfigure the interfaces for '
          'the Mininet hosts:\n', net.hosts, '\n' )


    net.start()
    info('Net Started--------------------------------\n\n\n')

    os.system('ovs-vsctl add-port s1 vxlan-intf')
    os.system('ovs-vsctl set interface vxlan-intf type=vxlan options:remote_ip=18.218.167.92')
    CLI( net )


    net.stop()
    info('Net Stopped--------------------------------\n\n\n')

