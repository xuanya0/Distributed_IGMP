# WSGI REST
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route

from collections import defaultdict

import json

Gateways_name = 'Gateway_API_App'

class EnhancedEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, set): return list(obj)
		return json.JSONEncoder.default(self, obj)

class ControllerClass(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(ControllerClass, self).__init__(req, link, data, **config)
		self.gateways_class = data[Gateways_name]

	@route(	name=None,
			path='/gateways/table/{dpid}',
			methods=['GET'])
	def list_table(self, req, **kwargs):

		gateways_class = self.gateways_class
		dpid = int(kwargs['dpid'])

		if dpid not in gateways_class.mac_to_port:
			return Response(status=404)

		ip_table = gateways_class.ip_to_mac.get(dpid, {})
		mac_table = gateways_class.mac_to_port.get(dpid, {})
		body = json.dumps({"ip_to_mac": ip_table, "mac_to_port": mac_table})

		return Response(content_type='application/json', body=body)

	@route(	name=None,
			path='/gateways/isolate/{dpid}/{port_no}',
			methods=['POST'])
	def isolate(self, req, **kwargs):

		gateways_class = self.gateways_class
		dpid = int(kwargs['dpid'])
		port_no = int(kwargs['port_no'])

		if dpid not in gateways_class.mac_to_port:
			return Response(status=404)

		if port_no == 0:
			for port_no in gateways_class.dpid_to_PortNo_to_HwAddr:
				gateways_class.port_down(dpid, port_no)
		else:
			gateways_class.port_down(dpid, port_no)

		body = json.dumps(
			{"isolated_dpids_ports": gateways_class.dpid_to_ports_to_isolate},
			cls=EnhancedEncoder)
		return Response(content_type='application/json', body=body)

	@route(	name=None,
			path='/gateways/deisolate/{dpid}/{port_no}',
			methods=['POST'])
	def deisolate(self, req, **kwargs):

		gateways_class = self.gateways_class
		dpid = int(kwargs['dpid'])
		port_no = int(kwargs['port_no'])

		if dpid not in gateways_class.mac_to_port:
			return Response(status=404)

		if port_no == 0:
			for port_no in gateways_class.dpid_to_PortNo_to_HwAddr:
				gateways_class.port_up(dpid, port_no)
		else:
			gateways_class.port_up(dpid, port_no)

		body = json.dumps(
			{"isolated_dpids_ports": gateways_class.dpid_to_ports_to_isolate},
			cls=EnhancedEncoder)
		return Response(content_type='application/json', body=body)

	@route(	name=None,
			path='/gateways/allocate/{dpid}',
			methods=['POST'])
	def allocate(self, req, **kwargs):

		dpid = int(kwargs['dpid'])
		gateways_class = self.gateways_class

		# if you allocate a dp with an ID already existing, refuse
		if dpid in gateways_class.dp_list:
			return Response(status=409, body="DPID already exists, refuse to update")


		# you should probably police the query args before feeding it to gateways, but ignore for now
		try:
			mpls_label = int(req.GET['mpls_label'])
		except:
			return Response(status=400, body='Error getting mpls_label')
		# TODO: police mpls label existence here

		try:
			nb_port = int(req.GET['nb_port'])
		except:
			return Response(status=400, body='Error getting northbound port')

		try:
			gw_ip = req.GET['gw_ip']
		except:
			return Response(status=400, body='Error getting gateway IP')
		# TODO: police gateway IP existence here

		try:
			gw_mac = req.GET['gw_mac']
		except:
			return Response(status=400, body='Error getting gateway MAC')

		try:
			smask = req.GET['smask']
		except:
			return Response(status=400, body='Error getting subnet mask')

		gateways_class.allocate_dpid(dpid, mpls_label, nb_port, gw_ip, gw_mac, smask)
		return Response()