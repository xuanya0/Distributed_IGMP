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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4

from ryu.lib import hub, ip
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, in_proto
from ryu.lib.packet import ether_types

# Custom lib
from lib.list_ethertypes import ethertype_bits_to_name
from lib.igmplib import IgmpQuerier
from lib.io import new_fifo_window


class Gateways(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(Gateways, self).__init__(*args, **kwargs)

		#tmp_fifo = '/tmp/xterm_ryu_monitor_1'
		#self.monitor1 = new_fifo_window(tmp_fifo)
		#self.monitor1.write("hello @ " + tmp_fifo)

		self.mac_to_port = {}
		self.ip_to_port = {}
		self.port_stats_requesters = []
		#self.monitor_thread = hub.spawn(self._monitor)
		self.queriers = []
		self.vtep_ports = {}
		self.reg_ports = {}
		self.igmp_queriers = {}

	def _monitor(self):
		while True:
			hub.sleep(3)
			# list your periodic tasks here

			# for it in self.port_stats_requesters:
			# 	it[0].send_msg(it[2])
			self.monitor1.write ("-------------------------------------------")
			for k,v in self.vtep_ports.iteritems():
				self.monitor1.write ("dp=",k)
				self.monitor1.write ("vtep ports",v)
			for k,v in self.reg_ports.iteritems():
				self.monitor1.write ("dp=",k)
				self.monitor1.write ("reg ports",v)


	# invoked such as when a switch connects to this controller
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		self.mac_to_port.setdefault(datapath.id, {})
		self.ip_to_port.setdefault(datapath.id, {})
		self.vtep_ports.setdefault(datapath.id, set())
		self.reg_ports.setdefault(datapath.id, set())

		# install table-miss flow entry.
		# Ryu says OFPCML_NO_BUFFER due to bug in OVS prior to v2.1.0
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		self.add_flow(datapath, 0, match, actions)

		# Always escalate control messages such as IGMP to controllers
		# priority has 16 bits, here use highest priority
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_IGMP)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		self.add_flow(datapath, 2**16-1, match, actions)

		# scan available ports
		#req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
		req = parser.OFPPortDescStatsRequest(datapath, 0)
		#self.port_stats_requesters.append((datapath,req,req2))
		datapath.send_msg(req)

		self.logger.info('Switch initialised: %s', datapath.id)


	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		ports = []
		for p in ev.msg.body:
			# check if such name exists in port name, just to pick out specific ports
			if ("tun" in p.name):
				self.vtep_ports[datapath.id].add(p.port_no)
			else:
				self.reg_ports[datapath.id].add(p.port_no)


		
		# instantiate up multicast classes (which auto-spawn threads)
		self.igmp_queriers[datapath.id] = IgmpQuerier(ev, self.reg_ports[datapath.id], self.vtep_ports[datapath.id], 'xterm_IGMP_monitor_'+str(datapath.id));



		self.logger.info('OFPPortDescStatsReply received: %s', datapath.id)


	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]

		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
								match=match, instructions=inst)
		datapath.send_msg(mod)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		
		# intercept LLDP and discard
		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		# Inspect IPv4
		if eth.ethertype == ether_types.ETH_TYPE_IP:
			ipv4_header = pkt.get_protocol(ipv4.ipv4)

			# Intercept IGMP
			if (ipv4_header.proto == in_proto.IPPROTO_IGMP):
				self.igmp_queriers[datapath.id].dispatcher(ev)
				return

			# Intercept IPv4 Multicasting without flows & Discard
			if (ip.text_to_int("224.0.0.0")     <= ip.text_to_int(ipv4_header.dst) 
				and 
				ip.text_to_int(ipv4_header.dst) < ip.text_to_int("239.255.255.255")):
				self.logger.info('discarding multicasting: %s', ipv4_header.dst)
				return


		# Default mode, basic layer2 switching
		self._layer2_switching(ev, eth)


	def _layer2_switching(self, ev, eth):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		dst = eth.dst
		src = eth.src

		dpid = datapath.id

		self.logger.info("packet in dp:%s port:%s type:%s\nsrc:%s dst:%s", 
			dpid, in_port, ethertype_bits_to_name[eth.ethertype],
			src, dst)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
			self.add_flow(datapath, 1, match, actions)

		# prevent flooding messaging from one vtep port to other vtep ports
		if (in_port in self.vtep_ports[dpid] and out_port == ofproto.OFPP_FLOOD):
			self.logger.info("flood packet at dp:%s in from port:%s", dpid, in_port)
			actions = [parser.OFPActionOutput(port_it) for port_it in self.reg_ports[dpid]]

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)

		datapath.send_msg(out)
