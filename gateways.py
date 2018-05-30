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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER ,CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4

from ryu.lib import hub, ip
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, in_proto, arp
from ryu.lib.packet import ether_types

# Custom lib
from lib.msg_decoder import ethertype_bits_to_name, ofpet_no_to_text
from lib.igmplib import IgmpQuerier
from lib.io import new_fifo_window


class Gateways(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(Gateways, self).__init__(*args, **kwargs)

		self.initialised_switches = set()


		# only remember ip/mac belonging to my own subnet
		self.ip_to_mac = {}
		self.mac_to_port = {}

		self.port_stats_requesters = []
		self.igmp_queriers = {}

		self.ipv4_fwd_table = 20

		
		# UI to be made for these preset parameters, this enables dynamic grid allocation --------------------------------
		self.dpid_to_mpls = {1: 1, 2: 2, 3: 3}
		# assign a subnet for each gateway, the first address being the gateway address
		# give the gateway a mac so that hosts can ARP
		self.dpid_to_subnet = {1: '172.16.1.0/24', 2: '172.16.2.0/24', 3: '172.16.3.0/24'}
		self.gw_ip = {1: '172.16.1.1', 2: '172.16.2.1', 3: '172.16.3.1'}
		self.gw_mac = {1: 'a6:65:bd:ca:2a:79', 2: 'a6:65:bd:ca:2a:17', 3: 'a6:65:bd:ca:2a:f2'}
		# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

		self.unhandled = {}

	# invoked such as when a switch connects to this controller
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		dp = ev.msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		# initialisation for the first handshake
		if dp.id in self.initialised_switches:
			return
		else:
			self.initialised_switches.add(dp.id)

		self.ip_to_mac.setdefault(dp.id, {})
		self.mac_to_port.setdefault(dp.id, {})

		# general rules--------------------flow table modification----------------------------vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

		# always elevate ARP to the controller in order to learn IP
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=2**16-1, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# for IPv4 packets, go to IPv4 table
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
		next_pipeline = parser.OFPInstructionGotoTable(self.ipv4_fwd_table)
		inst = [next_pipeline]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		# install table-miss flow entry.
		# Ryu says use OFPCML_NO_BUFFER due to bug in OVS prior to v2.1.0
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
		dp.send_msg(flow_mod)
		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table, priority=0, match=match, instructions=inst)
		dp.send_msg(flow_mod)
		# general rules--------------------flow table modification----------------------------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

		# install MPLS routing info for regular IP packet (unicast) to remote destinations
		for dst_dpid, subnet in self.dpid_to_subnet.items():
			if dp.id != dst_dpid:
				
				match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.dpid_to_subnet[dst_dpid])
				actions = [parser.OFPActionPushMpls(), 
							parser.OFPActionSetField(mpls_label=self.dpid_to_mpls[dst_dpid]),
							parser.OFPActionOutput(1)]
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
				flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table, priority=1, match=match, instructions=inst)
				dp.send_msg(flow_mod)


		# install MPLS routing info for incoming packets
		# pop MPLS header and run it through the ipv4 flow table
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS)
		pop_tag_set_mac = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionPopMpls(ether_types.ETH_TYPE_IP), parser.OFPActionSetField(eth_src=self.gw_mac[dp.id])])
		next_pipeline = parser.OFPInstructionGotoTable(self.ipv4_fwd_table)
		inst = [pop_tag_set_mac, next_pipeline]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		# instantiate IGMP classes (which auto-spawns threads)
		# assuming northbound port is always 1
		self.igmp_queriers[dp.id] = IgmpQuerier(ev, self.igmp_queriers, self.ipv4_fwd_table, self.dpid_to_mpls, 1, 'xterm_IGMP_monitor_'+str(dp.id))


		self.logger.info('Switch initialised: %s', dp.id)





	@set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
	def error_msg_handler(self, ev):
		msg = ev.msg

		self.logger.warning('OFPErrorMsg received:\n'
							'type=0x%02x %s\n'
							'code=0x%02x',
							msg.type, ofpet_no_to_text[msg.type],
							msg.code)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		
		# intercept LLDP and discard
		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return
		# intercept ARP
		elif eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_header = pkt.get_protocol(arp.arp)

			# learn ip_to_mac_to_port configuration
			self.ip_to_mac[dp.id][arp_header.src_ip] = arp_header.src_mac
			self.mac_to_port[dp.id][arp_header.src_mac] = in_port

			# reply to ARPing for gateway, then return
			if (arp_header.opcode == arp.ARP_REQUEST) and (arp_header.dst_ip == self.gw_ip[dp.id]):

				# reverse the src & dst
				arp_header.dst_mac = arp_header.src_mac
				arp_header.dst_ip = arp_header.src_ip

				# inject my identity
				arp_header.src_mac = self.gw_mac[dp.id]
				arp_header.src_ip = self.gw_ip[dp.id]
				arp_header.opcode = arp.ARP_REPLY

				eth.dst = eth.src
				eth.src = self.gw_mac[dp.id]

				p = packet.Packet()
				p.add_protocol(eth)
				p.add_protocol(arp_header)
				p.serialize()

				actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
				out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=p.data)
				dp.send_msg(out)
				return

		# Inspect IPv4 if available
		elif eth.ethertype == ether_types.ETH_TYPE_IP:
			ipv4_header = pkt.get_protocol(ipv4.ipv4)

			# Intercept IGMP
			if (ipv4_header.proto == in_proto.IPPROTO_IGMP):
				self.igmp_queriers[dp.id].dispatcher(ev)
				return

			# Intercept IPv4 Multicasting without flows & Discard
			if ((ip.text_to_int(ipv4_header.dst)>>28) == 0xE):
				self.logger.debug('discarding multicasting: %s', ipv4_header.dst)
				return

			# IPv4 switching if available -----------------------------------------------
			self._ipv4_switching(ev, ipv4_header)
			return
		
		# intercept non-IP and discard for debugging IGMP
		else:
			self.unhandled.setdefault(eth.ethertype, 0)

			self.unhandled[eth.ethertype] += 1

			# display discarded
			self.logger.debug('-----------------------')
			for k,v in self.unhandled.items():
				self.logger.debug('%s: %d', ethertype_bits_to_name[k], v)
			
			# discard!!!!!!!!!!!!!!!!!!!!!
			# return



		# Default mode, basic layer2 switching ------------------------------------------
		self._mac_switching(ev, eth)

	def _ipv4_switching(self, ev, ipv4_header):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']


		# print ("dpid=", dp.id, self.ip_to_mac[dp.id])
		# print (self.mac_to_port[dp.id])


		if ipv4_header.dst in self.ip_to_mac[dp.id]:
			dst_mac = self.ip_to_mac[dp.id][ipv4_header.dst]
			dst_port = self.mac_to_port[dp.id][dst_mac]
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_header.dst)
			actions = [parser.OFPActionSetField(eth_dst=dst_mac), parser.OFPActionOutput(dst_port)]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table, priority=1, match=match, instructions=inst, buffer_id=msg.buffer_id)
			dp.send_msg(flow_mod)

			# if unbuffered
			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
				actions = [parser.OFPActionOutput(dst_port)]
				out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
				dp.send_msg(out)


	def _mac_switching(self, ev, eth):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']

		self.logger.debug("packet in dp:%s port:%s type:%s\nsrc:%s dst:%s", 
			dp.id, in_port, ethertype_bits_to_name[eth.ethertype],
			eth.src, eth.dst)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dp.id][eth.src] = in_port

		# install flow for newly learnt mac
		match = parser.OFPMatch(eth_dst=eth.src)
		actions = [parser.OFPActionOutput(in_port)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# flood the ingress packet
		actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

		# if unbuffered
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			out_data = msg.data
		else:
			out_data = None

		out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=out_data)
		dp.send_msg(out)