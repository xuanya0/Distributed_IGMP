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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import igmp
from io import new_fifo_window

from time import time

# Cisco Query Interval == 60
QueryInterval = 60
class mcast_actioner():

	def __init__(self, ev):
		self.ev = ev
		msg = ev.msg
		self.dp = msg.datapath

		# each mcast address will be splitted into two action groups
		# one for local ports, one for upstream ports (remote)
		self._mcast_grp_to_actions = {}
		# dict -> action group -> port # -> taggings

	def add_port(self, mcast_AG_id, port, egress_tagging=None):
		# egress tagging should be in the format of a dict
		# e.g. {'vlan_vid': 0x1000}, {'mpls_label': 0x12345678}

		# create a dict if non-existent
		self._mcast_grp_to_actions.setdefault(mcast_AG_id, {})
		
		self._mcast_grp_to_actions[mcast_AG_id][port] = egress_tagging
		# new port added, install flow
		self.sync_flow(mcast_AG_id)

	def del_port(self, mcast_AG_id, port):
		self._mcast_grp_to_actions[mcast_AG_id].pop(port, None)
		self.sync_flow(mcast_AG_id)

	def sync_flow(self, mcast_AG_id):

		ofp = self.dp.ofproto
		ofp_parser = self.dp.ofproto_parser
		
		# ----------------------------------------------------------------
		# actions = [ofp_parser.OFPActionOutput(port) for port in self._mcast_grp_to_actions[mcast_AG_id]]
		# buckets = [ofp_parser.OFPBucket(actions=actions)]

		# some weird stuff, you obviously cannot have more than 1 output action in a single bucket?????
		buckets = []
		for port, egress_tagging in self._mcast_grp_to_actions[mcast_AG_id].items():
			actions=[]
			# destination is remote
			if egress_tagging:
				actions.append(ofp_parser.OFPActionSetField(**egress_tagging))

			actions.append(ofp_parser.OFPActionOutput(port))
			buckets.append(ofp_parser.OFPBucket(actions=actions))
		# ----------------------------------------------------------------

		mod = ofp_parser.OFPGroupMod(self.dp, ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, mcast_AG_id, buckets)
		self.dp.send_msg(mod)



class IgmpListeners():
	# this is a listener class that keeps track of downstream dst for mcast

	# A few timers according to RFC 3376
	# Robustness Variable: 2
	# Query Interval: 125
	# Query Response Interval: 100 (10 sec)

	def __init__(self, ports_in_grp, port_no, func_del_port):
		self.ports_in_grp = ports_in_grp
		self.port_no = port_no
		self.func_del_port = func_del_port

		self._timeout = QueryInterval + 10
		self.timer = 0
		self.listeners_addrs = set()

	def add_listener(self, addr):
		self.listeners_addrs.add(addr)

		# reset timer
		self.timer = 0

	def del_listener(self, addr):
		self.listeners_addrs.remove(addr)

		# check if empty. Commit suicide if true
		if not self.listeners_addrs:
			self.terminate()

	def timer_up(self, increment):
		self.timer += increment

		# Commit suicide if timeout
		if (self.timer >= self._timeout):
			self.terminate()

	def terminate(self):

		# remove myself from the action group and the mcast record
		self.func_del_port(self.port_no)
		self.ports_in_grp.pop(self.port_no)

class IgmpQuerier():
	
	def __init__(self, ev, reg_ports, vtep_ports, win_path=None):
		self.name = "IgmpQuerier"
		self.logger = logging.getLogger(self.name)

		msg = ev.msg
		dp = msg.datapath
		parser = dp.ofproto_parser

		self.dp = dp
		self.reg_ports = reg_ports
		self.vtep_ports = vtep_ports
		self._mcast = {}
		self._mcast_actioner = mcast_actioner(ev)


		# there are 0xfe tables
		# set up a flow table specifically for multicast
		self._from_local_table = 0x10
		self._from_remote_table = 0x11

		# set up two tables for different origins-------------------------------------------------------
		# redirect all multicast from local traffic to local table
		match = parser.OFPMatch(tunnel_id=0, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='224.0.0.0/4')
		inst = [parser.OFPInstructionGotoTable(self._from_local_table)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)

		# redirect all multicast from remote traffic to remote table
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='224.0.0.0/4')
		inst = [parser.OFPInstructionGotoTable(self._from_remote_table)]
		flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)
		# set up two tables for different origins-------------------------------------------------------

		# set the timer's resolution in second
		self.timing_resolution = 1

		#hub.spawn(self.test_thread, "args ==== " + str(datapath.id))
		self.querier_tid = hub.spawn(self._querying_thread)
		self.timeout_tid = hub.spawn(self._timer_thread)

		# spawn a monitor
		self.win_path = win_path
		if win_path:
			self.monitor_win = new_fifo_window(win_path)
			self.monitor_win.write("hello @", win_path, "this dpid:", str(dp.id))
			self.monitor_tid = hub.spawn(self._monitor_thread)

	def __del__(self):

		self.logger.info("IGMP@dp:%d going down-----------------------------", self.dp.id)
		if self.win_path:
			hub.kill(self.monitor_tid)
			# self.monitor_win.__del__()
			self.monitor_win = None


	def _monitor_thread(self):
		while True:
			self.monitor_win.write("----------Epoch: %s------------" % time())
			
			for grp in self._mcast:
				self.monitor_win.write("Multicast Group:", grp)
				for port in self._mcast[grp]:
					self.monitor_win.write("\tPort No:", port, "Timer:", self._mcast[grp][port].timer)
					self.monitor_win.write("\tListeners:\n\t\t", self._mcast[grp][port].listeners_addrs)
			
			hub.sleep(3)

	def _timer_thread(self):

		while True:

			for addr_grp, ports in self._mcast.items():
				# generate a list of keys to avoid error
				# since timer_up could delete a dict
				for port in ports.keys():  
					ports[port].timer_up(self.timing_resolution)

			hub.sleep(self.timing_resolution)





	def test_thread(self, *args, **kwargs):
		while True:
			print("igmplib::test_thread, printing its arguments:...")
			for arg in args:
				print(arg)
			hub.sleep(3)


	def dispatcher(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		req_pkt = packet.Packet(msg.data)
		req_igmp = req_pkt.get_protocol(igmp.igmp)
		req_ipv4 = req_pkt.get_protocol(ipv4.ipv4)
		if req_igmp:
			if   (req_igmp.msgtype == igmp.IGMP_TYPE_QUERY):
				self.monitor_win.write("Querier msg from elsewhere(another querier), to be supported: discard!!!")

				# should not forward remote queries to local, spamming end hosts
				# just forward the _mcast table to other controllers
			
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V1 or req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V2):
				self.monitor_win.write("IGMPv1/2 report in %s:---------------------------to be finished" % in_port)

				# forward this report to other controllers if this is from a regular port
				self._forward_regs_to_vteps(ev)
				self._report_handler(req_igmp, in_port, req_ipv4)
			
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3):
				self.monitor_win.write("IGMPv3 report in: not yet supported!!!")
			
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_LEAVE):
				self.monitor_win.write("IGMP leave------------------------------------to be finished")

				# forward this leave to other controllers if this is from a regular port
				self._forward_regs_to_vteps(ev)
				self._leave_handler(req_igmp, in_port, req_ipv4)

		else:
			self.logger.warning("Not an IGMP packet, impossible!!!")

	# forward IGMP reports leaves to other controller
	def _forward_regs_to_vteps(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']

		# don't forward from vtep to vteps, preventing loops
		if in_port in self.vtep_ports:
			return

		actions = [parser.OFPActionOutput(port) for port in self.vtep_ports if port != in_port]

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data
		out =  parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		dp.send_msg(out)



	# https://tools.ietf.org/html/rfc2236
	def _querying_thread(self):
		""" send a QUERY message periodically."""

		dp = self.dp

		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		# create a general query.
		res_igmp = igmp.igmp(
			msgtype=igmp.IGMP_TYPE_QUERY,
			maxresp=igmp.QUERY_RESPONSE_INTERVAL * 10,
			csum=0,
			address='0.0.0.0')
		res_ipv4 = ipv4.ipv4(
			total_length=len(ipv4.ipv4()) + len(res_igmp),
			proto=inet.IPPROTO_IGMP, ttl=1,
			src='0.0.0.0',
			dst=igmp.MULTICAST_IP_ALL_HOST)
		res_ether = ethernet.ethernet(
			dst=igmp.MULTICAST_MAC_ALL_HOST,
			src=dp.ports[ofproto.OFPP_LOCAL].hw_addr,
			ethertype=ether.ETH_TYPE_IP)
		res_pkt = packet.Packet()
		res_pkt.add_protocol(res_ether)
		res_pkt.add_protocol(res_ipv4)
		res_pkt.add_protocol(res_igmp)
		res_pkt.serialize()

		#query_ports = [parser.OFPActionOutput(port) for port in self.reg_ports]
		query_ports = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

		while True:
			# send a general query to the host that sent this message.
			out = parser.OFPPacketOut(
				datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
				data=res_pkt, in_port=ofproto.OFPP_LOCAL, actions=query_ports)
			dp.send_msg(out)
			hub.sleep(QueryInterval)
			self.logger.debug("dp %s, igmp query sent" % dp.id)

	def _report_handler(self, report, listeners_port, req_ipv4):
		"""the process when the querier received a REPORT message."""
		dp = self.dp
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		# Group id is 32-bit, the same length as IPv4, reuse it
		# for local listeners, use it's mcast addr as action group IP E0.0.0.0/4
		# for remote listeners, use mcast - 0x1000000 == D0.0.0.0/4
		dst_AG_id_local = ip.text_to_int(report.address)
		dst_AG_id_remote = ip.text_to_int(report.address) - 0x10000000

		# create two flow tables and  mcast group entries
		if (report.address not in self._mcast):
			self._mcast[report.address] = {}

			# add two multicast group entries
			grp_mod = parser.OFPGroupMod(dp, ofproto.OFPGC_ADD, ofproto.OFPGT_ALL, dst_AG_id_local, None)
			dp.send_msg(grp_mod)
			grp_mod = parser.OFPGroupMod(dp, ofproto.OFPGC_ADD, ofproto.OFPGT_ALL, dst_AG_id_remote, None)
			dp.send_msg(grp_mod)


			# install flows on both tables ----------------------------------------------------------vvvvvvvvvv
			# a mcast arrives untagged, this is originated locally, add entry to local table, fwd to local & remote AGs
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=report.address)
			actions = [parser.OFPActionGroup(group_id) for group_id in [dst_AG_id_local, dst_AG_id_remote]]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst, table_id=self._from_local_table)
			dp.send_msg(flow_mod)

			# a mcast arrives tagged, this is originated remotely, add entry to remote table, fwd to local AG only
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=report.address)
			actions = [parser.OFPActionGroup(group_id) for group_id in [dst_AG_id_local]]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst, table_id=self._from_remote_table)
			dp.send_msg(flow_mod)
			# install flows on both tables ----------------------------------------------------------^^^^^^^^^^


		# add an associated listeners class
		# this immediate expose traffic to a port
		if (listeners_port not in self._mcast[report.address]):
			# if a listener resides locally, no tagging
			if listeners_port in self.reg_ports:
				self._mcast_actioner.add_port(dst_AG_id_local, listeners_port)
				port_deleter = lambda port_to_be_deleted: self._mcast_actioner.del_port(
					dst_AG_id_local, 
					port_to_be_deleted)
			# if a listener resides remotely, tag the egress packet
			if listeners_port in self.vtep_ports:
				self._mcast_actioner.add_port(dst_AG_id_remote, listeners_port, {'tunnel_id': 0x00001234})
				port_deleter = lambda port_to_be_deleted: self._mcast_actioner.del_port(
					dst_AG_id_remote, 
					port_to_be_deleted)

			# start a listeners class in control plane for the first listener at this port
			self._mcast[report.address][listeners_port] = IgmpListeners(
				self._mcast[report.address],
				listeners_port, port_deleter)

		# add a listener
		self._mcast[report.address][listeners_port].add_listener(req_ipv4.src)

	def _leave_handler(self, leave, listeners_port, req_ipv4):
		"""the process when the querier received a LEAVE message."""
		if leave.address in self._mcast:
			if listeners_port in self._mcast[leave.address]:
				self._mcast[leave.address][listeners_port].del_listener(req_ipv4.src)


