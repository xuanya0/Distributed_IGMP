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
_mcast_flow_table = 30
_mcast_flow_cookie = 30


# this class controls the action on the switch, translating from RIB to FIB
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

	def add_port(self, mcast_grp_addr, port, remote_dpid=None):

		# create a dict for mcast grp if non-existent, for egress ports
		self._mcast_grp_to_actions.setdefault(mcast_grp_addr, {})
		# create a set for egress port if non-existent, for remote dpids
		self._mcast_grp_to_actions[mcast_grp_addr].setdefault(remote_dpid, set())

		self._mcast_grp_to_actions[mcast_grp_addr][remote_dpid].add(port)
		
		# new port added, install flow
		self.sync_flow(mcast_grp_addr)

	def del_port(self, mcast_grp_addr, port, remote_dpid=None):
		self._mcast_grp_to_actions[mcast_grp_addr][remote_dpid].discard(port)
		self.sync_flow(mcast_grp_addr)

	def sync_flow(self, mcast_grp_addr):
		# egress tagging should be in the format of a dict
		# e.g. {'vlan_vid': 0x1000}, {'mpls_label': 0x12345678}

		ofp = self.dp.ofproto
		ofp_parser = self.dp.ofproto_parser

		# let's try single action list see if it works
		local_actions = []
		remote_actions = [ofp_parser.OFPActionPushMpls()]
		for remote_dpid, ports_set in self._mcast_grp_to_actions[mcast_grp_addr].items():

			# if egress untagged, prepend in the action
			if not remote_dpid:
				for port in ports_set:
					local_actions.append(ofp_parser.OFPActionOutput(port))
			# if egress tagged, append in the action:
			else:
				for port in ports_set:
					remote_actions.append(ofp_parser.OFPActionSetField(mpls_label=self.dpid_to_mpls[remote_dpid]))
					remote_actions.append(ofp_parser.OFPActionOutput(port))

		if len(remote_actions) <= 1: remote_actions = []
		actions = local_actions + remote_actions
		inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

		# delete flows if no meaningful actions
		if len(actions) == 0:
			mod = ofp_parser.OFPFlowMod(datapath=self.dp, cookie=_mcast_flow_cookie, cookie_mask=2**64-1, table_id=_mcast_flow_table, 
				match=ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=mcast_grp_addr), priority=1,
				command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
		else:
			mod = ofp_parser.OFPFlowMod(datapath=self.dp, cookie=_mcast_flow_cookie, table_id=_mcast_flow_table, 
				match=ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=mcast_grp_addr), priority=1,
				instructions=inst)
		
		self.dp.send_msg(mod)

# this is a listeners class that keeps track of downstream dst for mcast
class IgmpListeners():

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

		# delete the mcast group address from the dictionary when the last igmp listeners' class suicides?

# IGMP handling class, essentially making every switch an IGMP querier
class IgmpQuerier():
	
	def __init__(self, 
			ev, 
			**kwargs):

		self.name = "IgmpQuerier"
		self.logger = logging.getLogger(self.name)

		msg = ev.msg
		dp = msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		self.dp = dp

		# remember args
		self.all_queriers = kwargs['all_queriers']
		self._ipv4_fwd_table_id = kwargs['ipv4_fwd_table_id']
		self.dpid_to_mpls = kwargs['dpid_to_mpls']
		self.dpid_to_nb_port = kwargs['dpid_to_nb_port']
		self.dpids_to_isolate = kwargs['dpids_to_isolate']
		self.win_path = kwargs['win_path']


		# mcast listeners_container/actioner instantiation
		self._mcast = {}
		self._mcast_actioner = mcast_actioner(ev, self.dpid_to_mpls)

		# there are 0xfe tables
		# set up a flow table specifically for multicast
		self._mcast_flow_table = _mcast_flow_table
		self._mcast_flow_cookie = _mcast_flow_cookie


		# Always elevate control messages such as IGMP to controllers
		# priority has 16 bits, here use TOP PRIORITY
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_IGMP)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self._ipv4_fwd_table_id, priority=2**16-1, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		# set up only ONE table for whatever packet origins--------------------------------------------------
		# redirect all multicast traffic from ipv4 table to mcast table
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='224.0.0.0/4')
		inst = [parser.OFPInstructionGotoTable(self._mcast_flow_table)]
		flow_mod = parser.OFPFlowMod(datapath=dp, table_id=self._ipv4_fwd_table_id, priority=1, match=match, instructions=inst)
		dp.send_msg(flow_mod)


		# set the timer's resolution in second
		self.timing_resolution = 1

		self.querier_tid = hub.spawn(self._querying_thread)
		self.timeout_tid = hub.spawn(self._timer_thread)

		# spawn a monitor
		if self.win_path:
			self.monitor_win = new_fifo_window(self.win_path)
			self.monitor_win.write("hello @", self.win_path, "this dpid:", str(dp.id))
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
			# self._mcast[addr_grp] == egress_dict
			for _, egress_dict in self._mcast.items():
				# generate a list of keys to avoid error
				# since timer_up could delete a dict
				for listeners in egress_dict.keys():  
					egress_dict[listeners].timer_up(self.timing_resolution)

			hub.sleep(self.timing_resolution)


	def dispatcher(self, ev):
		msg = ev.msg
		in_port = msg.match['in_port']

		req_pkt = packet.Packet(msg.data)
		req_igmp = req_pkt.get_protocol(igmp.igmp)
		req_ipv4 = req_pkt.get_protocol(ipv4.ipv4)
		if req_igmp:
			if   (req_igmp.msgtype == igmp.IGMP_TYPE_QUERY):
				self.monitor_win.write("Querier msg from remote (another querier): discard!!!")
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V1 or req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V2):
				# join locally
				self.join_handler(req_igmp, req_ipv4, in_port)
				# if IGMP in at an isolated DP, return
				if self.dp.id in self.dpids_to_isolate:
					return
				# join remotely except isolated DPs
				for remote_dpid, querier in self.all_queriers.items():
					if remote_dpid != self.dp.id and remote_dpid not in self.dpids_to_isolate:
					# send request directly within the controller
						querier.join_handler(req_igmp, req_ipv4, self.dpid_to_nb_port[remote_dpid], self.dp.id)
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3):
				self.monitor_win.write("IGMPv3 report in: not yet supported!!!")
			elif (req_igmp.msgtype == igmp.IGMP_TYPE_LEAVE):
				# leave locally
				self.leave_handler(req_igmp, req_ipv4, in_port)
				# if IGMP in at an isolated DP, return
				if self.dp.id in self.dpids_to_isolate:
					return
				# leave remotely except isolated DPs
				for remote_dpid, querier in self.all_queriers.items():
					if remote_dpid != self.dp.id and remote_dpid not in self.dpids_to_isolate:
					# send request directly within the controller
						querier.leave_handler(req_igmp, req_ipv4, self.dpid_to_nb_port[remote_dpid], self.dp.id)
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

		# mcast addr first used, create mcast group entries, install appropriate flows
		if (report.address not in self._mcast):
			self._mcast[report.address] = {}


		# add an associated listeners class
		# this immediate exposes traffic to a port
		if ((listeners_port, remote_dpid) not in self._mcast[report.address]):
			# if a listener resides remotely, tag the egress packet
			self._mcast_actioner.add_port(report.address, listeners_port, remote_dpid)

			# provide a method to delete flow when the last listener exits
			action_cleanup = lambda listeners_port, remote_dpid: self._mcast_actioner.del_port(report.address, listeners_port, remote_dpid)

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


