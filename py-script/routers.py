from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, in_proto, arp
from ryu.lib.packet import ether_types

# Custom lib
from lib.msg_decoder import ethertype_bits_to_name, ofpet_no_to_text
from lib.igmplib import IgmpQuerier
from lib.global_view import topo_view

class main(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(main, self).__init__(*args, **kwargs)

		self.logger.info("================instantiating topo_view================")
		self.topo_view = topo_view(dpid_to_hwaddr={
			4: '00:12:34:56:78:04' ,5: '00:12:34:56:78:05' ,6: '00:12:34:56:78:06'})
		self.logger.info("================exiting main init======================")

	# invoked when a switch connects to this controller
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		print ("=====new dp============")
		self.topo_view.new_dp(ev.msg.datapath)

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_reply_handler(self, ev):
		self.topo_view.port_stats_reply_handler(ev)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		ofp_parser = dp.ofproto_parser

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		# print ("main: packet ----------in")
		# intercept LLDP
		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			self.topo_view.dispatcher(ev)
	