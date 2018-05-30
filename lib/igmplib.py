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
from ryu.lib.packet import igmp
from io import new_fifo_window

from time import time

# Cisco Query Interval == 60
QueryInterval = 60
class mcast_actioner():

	def __init__(self, ev, dpid_to_mpls):
		self.ev = ev
		msg = ev.msg
		self.dp = msg.datapath
		self.dpid_to_mpls = dpid_to_mpls

		# each mcast address will be splitted into two action groups
		# one for local ports, one for upstream ports (remote)
		self._mcast_grp_to_actions = {}
		# dict -> action group -> port # -> taggings

	def add_port(self, mcast_AG_id, port, remote_dpid=None):

		# create a dict for mcast grp if non-existent, for egress ports
		self._mcast_grp_to_actions.setdefault(mcast_AG_id, {})
		# create a set for egress port if non-existent, for remote dpids
		self._mcast_grp_to_actions[mcast_AG_id].setdefault(remote_dpid, set())

		self._mcast_grp_to_actions[mcast_AG_id][remote_dpid].add(port)
		
		# new port added, install flow
		self.sync_flow(mcast_AG_id)

	def del_port(self, mcast_AG_id, port, remote_dpid=None):
		self._mcast_grp_to_actions[mcast_AG_id][remote_dpid].discard(port)
		self.sync_flow(mcast_AG_id)

	def sync_flow(self, mcast_AG_id):
		# egress tagging should be in the format of a dict
		# e.g. {'vlan_vid': 0x1000}, {'mpls_label': 0x12345678}

		ofp = self.dp.ofproto
		ofp_parser = self.dp.ofproto_parser
		
		# ----------------------------------------------------------------
		# actions = [ofp_parser.OFPActionOutput(port) for port in self._mcast_grp_to_actions[mcast_AG_id]]
		# buckets = [ofp_parser.OFPBucket(actions=actions)]

		
		# some weird stuff, you obviously cannot have more than 1 output action in a single bucket?????
		buckets = []
		for remote_dpid, ports_set in self._mcast_grp_to_actions[mcast_AG_id].items():
			actions = []
			# if egress untagged:
			if not remote_dpid:
				for port in ports_set:
					actions.append(ofp_parser.OFPActionOutput(port))
			# if egress tagged:
			else:
				actions.append(ofp_parser.OFPActionPushMpls())
				for port in ports_set:
					actions.append(ofp_parser.OFPActionSetField(mpls_label=self.dpid_to_mpls[remote_dpid]))
					actions.append(ofp_parser.OFPActionOutput(port))
			buckets.append(ofp_parser.OFPBucket(actions=actions))

		# # let's try single action list see if it works
		# actions = [ofp_parser.OFPActionPushMpls()]
		# for remote_dpid, ports_set in self._mcast_grp_to_actions[mcast_AG_id].items():

		# 	# if egress untagged, prepend in the action
		# 	if not remote_dpid:
		# 		for port in ports_set:
		# 			actions = [ofp_parser.OFPActionOutput(port)] + actions
		# 	# if egress tagged, append in the action:
		# 	else:
		# 		for port in ports_set:
		# 			actions.append(ofp_parser.OFPActionSetField(mpls_label=self.dpid_to_mpls[remote_dpid]))
		# 			actions.append(ofp_parser.OFPActionOutput(port))
		# buckets = [ofp_parser.OFPBucket(actions=actions)]
		# ----------------------------------------------------------------

		mod = ofp_parser.OFPGroupMod(self.dp, ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, mcast_AG_id, buckets)
		self.dp.send_msg(mod)



class IgmpListeners():
	# this is a listener class that keeps track of downstream dst for mcast

	# A few timers according to RFC 3376
	# Robustness Variable: 2
	# Query Interval: 125
	# Query Response Interval: 100 (10 sec)

	def __init__(self, ports_in_grp, port_no, remote_dpid, func_del_port):
		self.ports_in_grp = ports_in_grp
		self.port_no = port_no
		self.remote_dpid = remote_dpid
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
		self.func_del_port(self.port_no, self.remote_dpid)
		self.ports_in_grp.pop((self.port_no, self.remote_dpid))

class IgmpQuerier():
	
	def __init__(self, ev, all_queriers, ipv4_fwd_table, dpid_to_mpls, northbound, win_path=None):
		self.name = "IgmpQuerier"
		self.logger = logging.getLogger(self.name)

		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser


		self.dp = dp
		self.all_queriers = all_queriers
		# self.dpid_to_mpls = dpid_to_mpls
		self.northbound = northbound
		self._mcast = {}
		# self._mcast_listeners = mcast_listeners()
		self._mcast_actioner = mcast_actioner(ev, dpid_to_mpls)


		# there are 0xfe tables
		# set up a flow table specifically for multicast
		self._mcast_flow_table = 30
		self._ipv4_flow_table = ipv4_fwd_table


		# Always elevate control messages such as IGMP to controllers
		# priority has 16 bits, here use TOP PRIORITY
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_IGMP)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=ipv4_fwd_table, priority=2**16-1, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		# set up two tables for different origins-------------------------------------------------------
		# redirect all multicast traffic from ipv4 table to mcast table, HIGH PRIORITY
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='224.0.0.0/4')
		inst = [parser.OFPInstructionGotoTable(self._mcast_flow_table)]
		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=ipv4_fwd_table, priority=10, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		# set the timer's resolution in second
		self.timing_resolution = 1

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
				for port_dpid in self._mcast[grp]:
					self.monitor_win.write("port no, dpid:", port_dpid, "Timer:", self._mcast[grp][port_dpid].timer)
					self.monitor_win.write("\tListeners:\n\t\t", self._mcast[grp][port_dpid].listeners_addrs)
			
			hub.sleep(3)

	def _timer_thread(self):
		while True:
			for addr_grp, egress_dict in self._mcast.items():
				# generate a list of keys to avoid error
				# since timer_up could delete a dict
				for listeners in egress_dict.keys():  
					egress_dict[listeners].timer_up(self.timing_resolution)

			hub.sleep(self.timing_resolution)


	def dispatcher(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		in_port = msg.match['in_port']

		req_pkt = packet.Packet(msg.data)
		req_igmp = req_pkt.get_protocol(igmp.igmp)
		req_ipv4 = req_pkt.get_protocol(ipv4.ipv4)
		if req_igmp:
			if   (req_igmp.msgtype == igmp.IGMP_TYPE_QUERY):
				self.monitor_win.write("Querier msg from remote (another querier): discard!!!")
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V1 or req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V2):
				self.join_handler(req_igmp, req_ipv4, in_port)
				for dpid, querier in self.all_queriers.items():
					if dpid != self.dp.id:
					# northbound on all switches assumed to be 1
					# send request directly within the controller
						querier.join_handler(req_igmp, req_ipv4, 1, self.dp.id)
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3):
				self.monitor_win.write("IGMPv3 report in: not yet supported!!!")
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_LEAVE):
				self.leave_handler(req_igmp, req_ipv4, in_port)
				for dpid, querier in self.all_queriers.items():
					if dpid != self.dp.id:
					# northbound on all switches assumed to be 1
					# send request directly within the controller
						querier.leave_handler(req_igmp, req_ipv4, 1, self.dp.id)
		else:
			self.logger.warning("Not an IGMP packet, impossible!!!")

	# https://tools.ietf.org/html/rfc2236
	def _querying_thread(self):
		""" send a QUERY message periodically."""

		# delay 5 seconds before sending out the first
		hub.sleep(5)

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
			self.logger.debug("dp %s, igmp query sent" % dp.id)
			hub.sleep(QueryInterval)

	def join_handler(self, report, req_ipv4, listeners_port, remote_dpid=None):
		"""the process when the querier received a REPORT message."""
		dp = self.dp
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		# Group id is 32-bit, the same length as IPv4, reuse it
		# for local listeners, use it's mcast addr as action group IP E0.0.0.0/4
		# for remote listeners, use mcast - 0x1000000 == D0.0.0.0/4
		dst_AG_id = ip.text_to_int(report.address)

		# mcast addr first used, create mcast group entries, install appropriate flows
		if (report.address not in self._mcast):
			self._mcast[report.address] = {}

			# add multicast group entries
			grp_mod = parser.OFPGroupMod(dp, ofproto.OFPGC_ADD, ofproto.OFPGT_ALL, dst_AG_id, None)
			dp.send_msg(grp_mod)

			# install flows on tables ----------------------------------------------------------vvvvvvvvvv
			match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=report.address)
			actions = [parser.OFPActionGroup(dst_AG_id)]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			flow_mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst, table_id=self._mcast_flow_table)
			dp.send_msg(flow_mod)
			# install flows on tables ----------------------------------------------------------^^^^^^^^^^


		# add an associated listeners class
		# this immediate exposes traffic to a port
		if ((listeners_port, remote_dpid) not in self._mcast[report.address]):
			# if a listener resides remotely, tag the egress packet
			self._mcast_actioner.add_port(dst_AG_id, listeners_port, remote_dpid)

			# provide a method to delete flow when the last listener exits
			action_cleanup = lambda listeners_port, remote_dpid: self._mcast_actioner.del_port(dst_AG_id, listeners_port, remote_dpid)

			# start a listeners class in control plane for the first listener at this port
			self._mcast[report.address][(listeners_port, remote_dpid)] = IgmpListeners(
				self._mcast[report.address],
				listeners_port, 
				remote_dpid,
				action_cleanup)

		# add a listener (reset timer if already exists)
		self._mcast[report.address][(listeners_port, remote_dpid)].add_listener(req_ipv4.src)

	def leave_handler(self, report, req_ipv4, listeners_port, remote_dpid=None):
		"""the process when the querier received a LEAVE message."""
		if report.address in self._mcast:
			if (listeners_port, remote_dpid) in self._mcast[report.address]:
				self._mcast[report.address][(listeners_port, remote_dpid)].del_listener(req_ipv4.src)


