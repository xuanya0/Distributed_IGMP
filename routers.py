# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from lib.list_ethertypes import ethertype_bits_to_name

class SimpleRouter14(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleRouter14, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.dp_port_to_ip = {4:{3:'10.0.1.1'}, 5:{3:'10.0.2.1'}, 6:{3:'10.0.3.1'}}
		self.dp_port_hw_info = {}
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
		
		# router downstreams: 
		# interface IP/mask
		# s4: 10.0.1.1/24
		# s5: 10.0.2.1/24
		# s6: 10.0.3.1/24
		
		# installing static routes
		if (datapath.id == 4):
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.1.0/24")
			actions = [parser.OFPActionOutput(port=3)]
			self.add_flow(datapath, 1, match, actions)
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.2.0/24")
			actions = [parser.OFPActionOutput(port=1)]
			self.add_flow(datapath, 1, match, actions)
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.3.0/24")
			actions = [parser.OFPActionOutput(port=2)]
			self.add_flow(datapath, 1, match, actions)

		if (datapath.id == 5):
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.1.0/24")
			actions = [parser.OFPActionOutput(port=1)]
			self.add_flow(datapath, 1, match, actions)
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.2.0/24")
			actions = [parser.OFPActionOutput(port=3)]
			self.add_flow(datapath, 1, match, actions)
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.3.0/24")
			actions = [parser.OFPActionOutput(port=2)]
			self.add_flow(datapath, 1, match, actions)

		if (datapath.id == 6):
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.1.0/24")
			actions = [parser.OFPActionOutput(port=2)]
			self.add_flow(datapath, 1, match, actions)
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.2.0/24")
			actions = [parser.OFPActionOutput(port=1)]
			self.add_flow(datapath, 1, match, actions)
			
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.3.0/24")
			actions = [parser.OFPActionOutput(port=3)]
			self.add_flow(datapath, 1, match, actions)

		# query switches hw info
		req = parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)


	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		ports = []
		port_hw_info = {}
		for p in ev.msg.body:
			ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
						 'state=0x%08x properties=%s' %
						 (p.port_no, p.hw_addr,
						 p.name, p.config, p.state, repr(p.properties)))
			port_hw_info[p.port_no] = p.hw_addr
		# self.logger.info('OFPPortDescStatsReply received: %s', ports)
		
		self.dp_port_hw_info[ev.msg.datapath.id] = port_hw_info
		# self.logger.info(self.dp_port_hw_info)

		
		
	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]

		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
								match=match, instructions=inst)
		datapath.send_msg(mod)

	def arp_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		curr_dp = datapath.id
		in_port = ev.msg.match['in_port']

		in_arp_header = packet.Packet(ev.msg.data).get_protocols(arp.arp)[0]
		# [arp(dst_ip='10.0.1.1',dst_mac='00:00:00:00:00:00',hlen=6,hwtype=1,
		# opcode=1,plen=4,proto=2048,src_ip='10.0.1.2',src_mac='ca:4f:15:31:a4:3c')]
		
		# ignore ARP reply 
		if (in_arp_header.opcode == 2):
			return
		
		# ignore those not destined to me
		if (in_arp_header.dst_ip != self.dp_port_to_ip[curr_dp][in_port]):
			return
		
		self.logger.info("arp response!!!")


		arp_resp = arp.arp(arp.ARP_HW_TYPE_ETHERNET, ether_types.ETH_TYPE_IP, 6, 4, opcode=2, 
			src_mac= self.dp_port_hw_info[curr_dp][in_port], 
			src_ip=  self.dp_port_to_ip[curr_dp][in_port], 
			dst_mac= in_arp_header.src_mac, 
			dst_ip=  in_arp_header.src_ip)

		eth_frame = ethernet.ethernet(dst='FF:FF:FF:FF:FF:FF', #in_arp_header.src_mac, 
			src=self.dp_port_hw_info[curr_dp][in_port], 
			ethertype=ether_types.ETH_TYPE_ARP)
		pkt = packet.Packet()
		pkt.add_protocol(eth_frame)
		pkt.add_protocol(arp_resp)
		pkt.serialize()


		actions = [parser.OFPActionOutput(in_port)]
		out_msg = parser.OFPPacketOut(datapath=datapath,
			buffer_id=0xffffffff,
			in_port=ofproto.OFPP_CONTROLLER, 
			actions=actions, 
			data=pkt.data)
		datapath.send_msg(out_msg)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		# ignore lldp packet
		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return
		
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			self.arp_handler(ev)
		
		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})


		self.logger.info("packet in dp:%s port:%s src:%s dst:%s\nType:%s", dpid, in_port, src, dst, ethertype_bits_to_name[eth.ethertype])
