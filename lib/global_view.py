# Copyright (C) 2018 XuanYao Zhang @ University of Illinois at Urbana-Champaign
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Inspired by functions in https://github.com/osrg/ryu/blob/master/ryu/lib/igmplib.py
import logging
import struct

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import hub, ip
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet, in_proto
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import igmp, lldp

from io import new_fifo_window
from collections import defaultdict

from time import time

ProbingInterval = 1
timer_res = 1
timeout = 10


class neigh_dp():
	def __init__(self):
		# from lldp
		self.peer_dpid = None
		self.last_prober_ts = 0

		# from port querying
		self.length = 0
		self.port_no = None
		self.duration_sec = 0
		self.duration_nsec = 0
		self.rx_packets = 0
		self.tx_packets = 0
		self.rx_bytes = 0
		self.tx_bytes = 0
		self.rx_dropped = 0
		self.tx_dropped = 0
		self.rx_errors = 0
		self.tx_errors = 0
		# from calculation from port query
		self.rate_rx_packets = 0
		self.rate_tx_packets = 0
		self.rate_rx_bytes = 0
		self.rate_tx_bytes = 0
		self.rate_rx_dropped = 0
		self.rate_tx_dropped = 0
		self.rate_rx_errors = 0
		self.rate_tx_errors = 0

class dp_container():
	def __init__(self):
		self.this_dp = None
		self.neighbour_list = defaultdict(neigh_dp)
		self.prober = None
		self.hwaddr = None




# Discovering Topology of the Network
class topo_view():
	
	def __init__(self, **kwargs):

		self.name = "topo_view"
		self.logger = logging.getLogger(self.name)


		self.dps = defaultdict(dp_container)
		
		dpid_to_hwaddr = kwargs['dpid_to_hwaddr']
		for dpid, hwaddr in dpid_to_hwaddr.items():
			self.dps[dpid].hwaddr = hwaddr

		# neighbours [dp.id] [port] ===> struct

		# set the timer's resolution in second
		self._link_prober_thread = hub.spawn(self._link_prober)
		self._timer_out_thread = hub.spawn(self._timer_out)
		self._switch_querier_thread = hub.spawn(self._switch_querier)


	def new_dp(self, dp):

		# Let's go with LLDP for topology build-up
		# priority has 16 bits, here use TOP PRIORITY
		match = dp.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
		actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER)]
		inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, table_id=0, priority=2**16-1, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		layer_lldp = lldp.lldp(tlvs=[lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,chassis_id=str(dp.id)),
									lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,port_id='0'), 
									lldp.TTL(ttl=1), 
									lldp.End()])
		layer_ether = ethernet.ethernet(
			dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
			src=self.dps[dp.id].hwaddr,
			ethertype=ether.ETH_TYPE_LLDP)
		pkt = packet.Packet()
		pkt.add_protocol(layer_ether)
		pkt.add_protocol(layer_lldp)
		pkt.serialize()
		

		print ("depositing new dp............")
		self.dps[dp.id].this_dp = dp
		self.dps[dp.id].prober = pkt

	def _link_prober(self):
		""" send a QUERY message periodically."""

		# delay 5 seconds before sending out the first
		hub.sleep(2)

		# create a general query.

		# periodic probing
		while True:
			# send a general query to the host that sent this message.
			for dpid, dp_container in self.dps.items():
				dp = dp_container.this_dp


				query_ports = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_FLOOD)]
				out = dp.ofproto_parser.OFPPacketOut(
					datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
					data=dp_container.prober, in_port=dp.ofproto.OFPP_LOCAL, actions=query_ports)
				dp.send_msg(out)
			# print ("my dps:", self.dps)
			hub.sleep(ProbingInterval)
	
	def _switch_querier(self):

		# delay 5 seconds before sending out the first
		hub.sleep(2)

		while True:
			hub.sleep(ProbingInterval)
			# send a general query to the host that sent this message.
			for dpid, dp_container in self.dps.items():
				hub.sleep(ProbingInterval)
				
				dp = dp_container.this_dp
				req = dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
				dp.send_msg(req)

			

	def port_stats_reply_handler(self, ev):

		dp = ev.msg.datapath
		print ("stats begin vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
		# calculate
		for stat in ev.msg.body:
			
			if stat.port_no == dp.ofproto.OFPP_LOCAL: continue 
				
			this_neigh = self.dps[dp.id].neighbour_list[stat.port_no]
			
			# if dp.id and stat.port_no : 
			# 	print ("dpid:", dp.id, stat.port_no, "rate tx:", stat.tx_packets, this_neigh.tx_packets, stat.tx_packets - this_neigh.tx_packets)
			# 	print ("identify:", id(self.dps[dp.id]), id(this_neigh))

			# time span in nano seconds
			timespan = (stat.duration_sec - this_neigh.duration_sec) + float(stat.duration_nsec - this_neigh.duration_nsec)/(10**9)

			# calculate the rate first
			this_neigh.rate_rx_packets = float(stat.rx_packets - this_neigh.rx_packets)/timespan
			this_neigh.rate_tx_packets =  float(stat.tx_packets - this_neigh.tx_packets)/timespan
			this_neigh.rate_rx_bytes = float(stat.rx_bytes - this_neigh.rx_bytes)/timespan
			this_neigh.rate_tx_bytes = float(stat.tx_bytes - this_neigh.tx_bytes)/timespan
			this_neigh.rate_rx_dropped = float(stat.rx_dropped - this_neigh.rx_dropped)/timespan
			this_neigh.rate_tx_dropped = float(stat.tx_dropped - this_neigh.tx_dropped)/timespan
			this_neigh.rate_rx_errors = float(stat.rx_errors - this_neigh.rx_errors)/timespan
			this_neigh.rate_tx_errors = float(stat.tx_errors - this_neigh.tx_errors)/timespan

			# update the last record
			this_neigh.duration_sec = stat.duration_sec
			this_neigh.duration_nsec = stat.duration_nsec
			this_neigh.rx_packets = stat.rx_packets
			this_neigh.tx_packets = stat.tx_packets
			this_neigh.rx_bytes = stat.rx_bytes
			this_neigh.tx_bytes = stat.tx_bytes
			this_neigh.rx_dropped = stat.rx_dropped
			this_neigh.tx_dropped = stat.tx_dropped
			this_neigh.rx_errors = stat.rx_errors
			this_neigh.tx_errors = stat.tx_errors

			print ("rate tx:", this_neigh.rate_tx_bytes)

		print ("stats ends ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	# a timeout thread that check the timestamp of the classes.
	# if the (curr_time - last_update_ts) > timeout_val
	# time out the object
	def _timer_out(self):
		while True:
			hub.sleep(timer_res)
			for dpid, dp in self.dps.items():
				hub.sleep(timer_res)

				for inport, neigh_dp in dp.neighbour_list.items():
					if time() - neigh_dp.last_prober_ts > timeout:
						print ("dpid:", dpid, "in_port", inport)
						print ("timed out, peer_dpid:", neigh_dp.peer_dpid)
	
	
	# responsible for only LLDP
	def dispatcher(self, ev):
		# self.logger.info("global_view: dispatcher triggered")
		
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)
		lldp_header = pkt.get_protocol(lldp.lldp)

		# neighbours [dp.id] [port] ===> struct
		
		#print ("packet in---------------------------------:", lldp_header)
		if lldp_header:
			self.dps[dp.id].neighbour_list[in_port].peer_dpid = lldp_header.tlvs[0].chassis_id
		# else:
		# 	print ("malformed packet?????????????????????????????? data len:", len(msg.data))
		# 	print (pkt)
		self.dps[dp.id].neighbour_list[in_port].last_prober_ts = time()




