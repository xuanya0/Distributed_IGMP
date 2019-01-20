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
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, in_proto, arp
from ryu.lib.packet import ether_types
from ryu.lib import ip

# WSGI REST
from ryu.app.wsgi import WSGIApplication

# Custom lib
from lib.msg_decoder import ethertype_bits_to_name, ofpet_no_to_text
from lib.igmplib import IgmpQuerier
from lib.rest_api import ControllerClass, Gateways_name
from collections import defaultdict

highest_priority = 2**16 - 1
flow_isolation_cookie = 10


"""
	Table 0 priority:
	Ether_type categorisation (ARP, IP, MPLS)
	Ethernet unicast
	Table miss

	Table 20(IP) priority:
	Local IP unicast
	*Remote dst intercepting.
	Remote IP unicast == Remote IP multicast
	Table miss


"""


class Gateways(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}

	def __init__(self, *args, **kwargs):
		super(Gateways, self).__init__(*args, **kwargs)

		self.initialised_switches = set()

		# only remember ip/mac belonging to my own subnet
		self.ip_to_mac = {}
		self.mac_to_port = {}

		self.port_stats_requesters = []
		self.igmp_queriers = {}

		self.ipv4_fwd_table_id = 20

		# UI to be made for these preset parameters, this enables dynamic grid
		self.dpid_to_mpls = {1: 1, 2: 2, 3: 3}
		self.dpid_to_nb_port = {1: 1, 2: 1, 3: 1}
		self.dpids_to_isolate = set()
		# assign a subnet for each gateway, the first address being the gateway address
		# give the gateway a mac so that hosts can ARP
		self.dpid_to_gw_ip = {1: '172.16.1.1',
							  2: '172.16.2.1', 
							  3: '172.16.3.1'}
		self.dpid_to_smask = {1: '255.255.255.0',
							  2: '255.255.255.0', 
							  3: '255.255.255.0'}
		self.dpid_to_gw_mac = {1: 'a6:65:bd:ca:2a:79',
							   2: 'a6:65:bd:ca:2a:17', 
							   3: 'a6:65:bd:ca:2a:f2'}
		self.dpid_to_nb_hw_addr = self.dpid_to_gw_mac
		self.dpid_to_PortNo_to_HwAddr = defaultdict(dict)
		self.dpid_to_ports_to_isolate = defaultdict(set)

		self.dp_list = {}
		# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

		self.unhandled = {}

		# REST API Initialisation
		# if kwargs['wsgi'] is not None:
		wsgi = kwargs['wsgi']
		wsgi.register(ControllerClass, {Gateways_name: self})

	# invoked when a switch connects to this controller
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
		self.dp_list[dp.id] = dp

		# general rules--------------------flow table
		# modification----------------------------vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

		# always elevate ARP to the controller in order to learn IP (OFPCML_NO_BUFFER for certain OVS version)
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(
			ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(
			datapath=dp, priority=highest_priority, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# always flood IEC 61850/GOOSE (EtherType: 0x88b8)
		match = parser.OFPMatch(eth_type=0x88b8)
		actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD, ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(
			ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(
			datapath=dp, priority=highest_priority, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# for IPv4 packets, go to IPv4 table
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
		next_pipeline = parser.OFPInstructionGotoTable(self.ipv4_fwd_table_id)
		inst = [next_pipeline]
		flow_mod = parser.OFPFlowMod(
			datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# install table-miss flow entry.
		# Ryu says use OFPCML_NO_BUFFER due to bug in OVS prior to v2.1.0
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
		dp.send_msg(flow_mod)
		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table_id, priority=0, match=match, instructions=inst)
		dp.send_msg(flow_mod)
		# general rules--------------------flow table modification-------------

		# install MPLS routing info for regular IP packet (unicast) to remote
		# destinations
		for dst_dpid, dst_gw_ip in self.dpid_to_gw_ip.items():
			if dp.id != dst_dpid:

				match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=(
					dst_gw_ip, self.dpid_to_smask[dst_dpid]))
				actions = [parser.OFPActionPushMpls(),
						   parser.OFPActionSetField(mpls_label=self.dpid_to_mpls[dst_dpid]),
						   parser.OFPActionOutput(1)]
				inst = [parser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
				flow_mod = parser.OFPFlowMod(
					datapath=dp, table_id=self.ipv4_fwd_table_id, priority=10, match=match, instructions=inst)
				dp.send_msg(flow_mod)

		# install MPLS routing info for incoming packets
		# pop MPLS header and run it through the ipv4 flow table
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS)
		pop_tag_set_mac = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [
			parser.OFPActionPopMpls(ether_types.ETH_TYPE_IP), 
			parser.OFPActionSetField(eth_src=self.dpid_to_gw_mac[dp.id])])
		next_pipeline = parser.OFPInstructionGotoTable(self.ipv4_fwd_table_id)
		inst = [pop_tag_set_mac, next_pipeline]
		flow_mod = parser.OFPFlowMod(
			datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# instantiate IGMP classes (which auto-spawns threads)
		# assuming northbound port is always 1
		self.igmp_queriers[dp.id] = IgmpQuerier(ev, **{
			"all_queriers": self.igmp_queriers,
			"ipv4_fwd_table_id": self.ipv4_fwd_table_id,
			"dpid_to_mpls": self.dpid_to_mpls,
			"dpid_to_nb_port": self.dpid_to_nb_port,
			"dpids_to_isolate": self.dpids_to_isolate,
			"win_path": 'xterm_IGMP_monitor_' + str(dp.id)})
		# "win_path":				None})

		# query switch for port description
		req = parser.OFPPortDescStatsRequest(dp)
		dp.send_msg(req)

		self.logger.info('Switch initialised: %s', dp.id)

	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		dp = ev.msg.datapath

		for port in ev.msg.body:
			self.dpid_to_PortNo_to_HwAddr[dp.id][port.port_no] = port.hw_addr


	@set_ev_cls(ofp_event.EventOFPErrorMsg, [
				HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
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

		# intercept ARP then return
		elif eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_header = pkt.get_protocol(arp.arp)

			# discard packets from unrecognized subnet
			# to deal with problem stemming from link-local addr autoconfig
			if not self._same_subnet(
					arp_header.src_ip, 
					self.dpid_to_gw_ip[dp.id], 
					self.dpid_to_smask[dp.id]):	
				return

			# ethernet flow mod
			self._eth_flow_mod(ev, eth)
			# ipv4 flow mod
			self._ipv4_flow_mod(ev, eth, arp_header.src_ip)

			# reply to ARPs for gateway, no l2 switching
			if (arp_header.opcode == arp.ARP_REQUEST) and (
					arp_header.dst_ip == self.dpid_to_gw_ip[dp.id]):

				# reverse the src & dst
				arp_header.dst_mac = arp_header.src_mac
				arp_header.dst_ip = arp_header.src_ip

				# inject my identity
				arp_header.src_mac = self.dpid_to_gw_mac[dp.id]
				arp_header.src_ip = self.dpid_to_gw_ip[dp.id]
				arp_header.opcode = arp.ARP_REPLY

				eth.dst = eth.src
				eth.src = self.dpid_to_gw_mac[dp.id]

				p = packet.Packet()
				p.add_protocol(eth)
				p.add_protocol(arp_header)
				p.serialize()

				actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
				out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=p.data)
				dp.send_msg(out)
			# ARPs for another host, flood it
			else:
				self._flooding(ev)
			return

		# Inspect IPv4 if available
		elif eth.ethertype == ether_types.ETH_TYPE_IP:
			ipv4_header = pkt.get_protocol(ipv4.ipv4)

			# discard packets from unrecognized subnet
			# to deal with problem stemming from link-local addr autoconfig
			if not self._same_subnet(
					ipv4_header.src, 
					self.dpid_to_gw_ip[dp.id], 
					self.dpid_to_smask[dp.id]):
				return


			# Intercept IGMP (must return afterwards, or leaks into other dps)
			if (ipv4_header.proto == in_proto.IPPROTO_IGMP):
				self.igmp_queriers[dp.id].dispatcher(ev)
				return

			# For non-IGMP, learn ipv4?
			# self._ipv4_flow_mod(ev, eth, ipv4_header.src)

		# Other ether_type unrecognised by controller, do some statistics, then
		# flood
		else:
			self.unhandled.setdefault(eth.ethertype, 0)
			self.unhandled[eth.ethertype] += 1
			# display discarded
			self.logger.debug('-----------------------')
			for k, v in self.unhandled.items():
				self.logger.debug('%s: %d', ethertype_bits_to_name[k], v)
			self._flooding(ev)

	def _same_subnet(self, alpha, bravo, smask):

		alpha_int = alpha if type(alpha) == type(int()) else ip.ipv4_to_int(alpha)
		bravo_int = bravo if type(bravo) == type(int()) else ip.ipv4_to_int(bravo)
		smask_int = smask if type(smask) == type(int()) else ip.ipv4_to_int(smask)
		
		if (alpha_int ^ bravo_int) & smask_int:
			print (alpha + ' and ' + bravo + ' are not in the same subnet: ' + smask)
		
		return (alpha_int ^ bravo_int) & smask_int == 0

	# should only be called for locally generated packets
	def _ipv4_flow_mod(self, ev, eth, src_ip):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		# learn an ip address
		self.ip_to_mac[dp.id][src_ip] = eth.src

		if eth.src in self.mac_to_port[dp.id]:
			src_port = self.mac_to_port[dp.id][eth.src]

			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)
			actions = [parser.OFPActionSetField(eth_dst=eth.src), parser.OFPActionOutput(src_port)]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table_id, priority=100, match=match, instructions=inst, buffer_id=msg.buffer_id)
			dp.send_msg(flow_mod)

	# should only be called for locally generated packets
	def _eth_flow_mod(self, ev, eth):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']

		self.logger.debug("packet in dp:%s port:%s type:%s\nsrc:%s dst:%s",
						  dp.id, in_port, ethertype_bits_to_name[eth.ethertype],
						  eth.src, eth.dst)

		# learn a mac address
		self.mac_to_port[dp.id][eth.src] = in_port

		# install flow for newly learnt mac
		match = parser.OFPMatch(eth_dst=eth.src)
		actions = [parser.OFPActionOutput(in_port)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)

	def _flooding(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']

		# flood the ingress packet
		actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		# if unbuffered
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			out_data = msg.data
		else:
			out_data = None

		out = parser.OFPPacketOut(
			datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=out_data)
		dp.send_msg(out)

	def port_down(self, target_dpid, target_port):

		# # ***hold off this implementation for now***
		# # make other dps reject incoming traffic from this dp
		# for other_dpid, dp in dp_list.items():
		# 	if other_dpid != target_dpid:
		# 		other_dp = self.dp_list[other_dpid]
		# 		ofp = other_dp.ofproto
		# 		parser = other_dp.ofproto_parser
		# 		# reject IPv4 traffic from target_dpid (unicast+multicast)
		# 		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=self.dpid_to_subnet???[target_dpid])
		# 		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table_id, priority=highest_priority, match=match)
		# 		other_dp.send_msg(flow_mod)
		# 		# reject IPv4 traffic towards target_dpid (unicast)
		# 		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.dpid_to_subnet???[target_dpid])
		# 		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table_id, priority=highest_priority, match=match)
		# 		other_dp.send_msg(flow_mod)

		# 		# set target_dpid's northbound port to null or an invalid port
		# 		pass
		# 		# self.igmp_queriers[target_dpid]._mcast_actioner.sync_flow()

		# make this dp reject all northbound traffic by disabling northbound
		# port
		target_dp = self.dp_list[target_dpid]
		ofp = target_dp.ofproto
		parser = target_dp.ofproto_parser

		port_mod = parser.OFPPortMod(target_dp,
									 target_port,
									 self.dpid_to_PortNo_to_HwAddr[target_dpid][target_port],
									 0b11111111, ofp.OFPPC_PORT_DOWN)
		target_dp.send_msg(port_mod)

		self.dpid_to_ports_to_isolate[target_dpid].add(target_port)
		if target_port == 0 or target_port == self.dpid_to_nb_port[target_dpid]:
			self.dpids_to_isolate.add(target_dpid)

	def port_up(self, target_dpid, target_port):

		target_dp = self.dp_list[target_dpid]
		ofp = target_dp.ofproto
		parser = target_dp.ofproto_parser

		port_mod = parser.OFPPortMod(target_dp,
									 target_port,
									 self.dpid_to_PortNo_to_HwAddr[target_dpid][target_port],
									 0, ofp.OFPPC_PORT_DOWN)
		target_dp.send_msg(port_mod)

		self.dpid_to_ports_to_isolate[target_dpid].discard(target_port)
		if target_port == 0 or target_port == self.dpid_to_nb_port[target_dpid]:
			self.dpids_to_isolate.discard(target_dpid)

	def allocate_dpid(self, dpid, mpls_label, nb_port, gw_ip, gw_mac, smask):

		# Update static grid configuration
		self.dpid_to_mpls[dpid] = mpls_label
		self.dpid_to_nb_port[dpid] = nb_port
		self.dpid_to_gw_ip[dpid] = gw_ip
		self.dpid_to_smask[dpid] = smask
		self.dpid_to_gw_mac[dpid] = gw_mac

		# re-install flows in all existing DPIDs to upgrade the flow
		for _, dp in self.dp_list.items():
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			# install MPLS routing info for regular IP packet (unicast) to
			# remote destinations
			for dst_dpid, dst_gw_ip in self.dpid_to_gw_ip.items():
				if dp.id != dst_dpid:
					match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=(
						dst_gw_ip, self.dpid_to_smask[dst_dpid]))
					actions = [parser.OFPActionPushMpls(),
							   parser.OFPActionSetField(mpls_label=self.dpid_to_mpls[dst_dpid]),
							   parser.OFPActionOutput(1)]
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
					flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self.ipv4_fwd_table_id, priority=10, match=match, instructions=inst)
					dp.send_msg(flow_mod)
