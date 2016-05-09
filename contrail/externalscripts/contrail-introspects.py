#!/usr/bin/env python
import requests
import xmltodict
import sys
import argparse
import json
import re

FAILED = 0
ACTIVE = 1
PASSIVE = 2

STATUS = {
    "Yes": ACTIVE,
    "Established": ACTIVE,
    "No": FAILED
}

URLS = {
    "node_status": "Snh_SandeshUVECacheReq?x=NodeStatus",
    "xmpp_status": "Snh_AgentXmppConnectionStatusReq",
    "bgp_peer_status": "Snh_ShowBgpNeighborSummaryReq"
}

PORTS = {
    "schema": 8087,
    "vrouter-agent": 8085,
    "control": 8083,
    "config-api": 8084,
    "analytics-api": 8090,
    "collector": 8089,
    "alarm-gen": 5995,
    "discovery": 5997,
    "dns": 8092,
    "svc-monitor": 8088
}


class IntrospectReader(object):

    def __init__(self, host):
        self.host = host

    @staticmethod
    def get_dict_from_introspect(url, to_dict=True):
        try:
            r = requests.get(url)
#            print r.text
            if to_dict:
                return (True, xmltodict.parse(r.text),)
            else:
                return (True, r.text,)
        except requests.exceptions.ConnectionError:
            return (False, {},)

    def node_status(self, service, port=None):
        if not port:
            port = PORTS[service]
        rv, x = self.get_dict_from_introspect('http://%s:%s/%s' % (self.host, port, URLS["node_status"]), False)
        if rv:
            if re.match(r'.*<state.*Functional.*</state>',x):
                return ACTIVE
            else:
                return FAILED
        else:
            return PASSIVE

    def bgp_status(self, controller_ip, port=None):
        if not port:
            port = PORTS['control']
        rv, x = self.get_dict_from_introspect('http://%s:%s/%s' % (self.host, port, URLS["bgp_peer_status"]))

        if isinstance(x['ShowBgpNeighborSummaryResp']['neighbors']['list']['BgpNeighborResp'],list):
            for i in x['ShowBgpNeighborSummaryResp']['neighbors']['list']['BgpNeighborResp']:
                if i['peer_address']['#text'] == controller_ip:
                    return STATUS[i['state']['#text']]
            return STATUS['No']
        else:
            return STATUS[x['ShowBgpNeighborSummaryResp']['neighbors']['list']['BgpNeighborResp']['state']['#text']]

    def bgp_detect(self, port=None):
        if not port:
            port = PORTS['control']
        rv, x = self.get_dict_from_introspect('http://%s:%s/%s' % (self.host, port, URLS["bgp_peer_status"]))
        controllers=[]
        if isinstance(x['ShowBgpNeighborSummaryResp']['neighbors']['list']['BgpNeighborResp'],list):
            for i in x['ShowBgpNeighborSummaryResp']['neighbors']['list']['BgpNeighborResp']:
                if i['encoding']['#text'] == 'BGP':
                    controllers.append({"{#CONTROLLER_IP}": i['peer_address']['#text']})
        else:
            controllers.append({
                "{#CONTROLLER_IP}": x['ShowBgpNeighborSummaryResp']['neighbors']['list']['BgpNeighborResp']['peer_address']['#text']
            })

        return json.dumps({"data": controllers})

    def xmpp_status(self, controller_type, port=None, controller_ip=None):
        if not port:
            port = PORTS['vrouter-agent']

        rv, x = self.get_dict_from_introspect('http://%s:%s/%s' % (self.host, port, URLS["xmpp_status"]))
        if isinstance(x['AgentXmppConnectionStatus']['peer']['list']['AgentXmppData'],list):
            for i in x['AgentXmppConnectionStatus']['peer']['list']['AgentXmppData']:
                if controller_ip:
                    if i['controller_ip']['#text'] == controller_ip:
                        return STATUS[i[controller_type]['#text']]
                else:
                    if i[controller_type]['#text'] == 'Yes':
                        return STATUS['Yes']
            return STATUS['No']
        else:
            return STATUS[x['AgentXmppConnectionStatus']['peer']['list']['AgentXmppData'][controller_type]['#text']]

    def xmpp_detect(self, port=None):
        if not port:
            port = PORTS['vrouter-agent']

        rv, x = self.get_dict_from_introspect('http://%s:%s/%s' % (self.host, port, URLS["xmpp_status"]))
        controllers=[]
        if isinstance(x['AgentXmppConnectionStatus']['peer']['list']['AgentXmppData'],list):
            for i in x['AgentXmppConnectionStatus']['peer']['list']['AgentXmppData']:
                controllers.append({"{#CONTROLLER_IP}": i['controller_ip']['#text']})
        else:
            controllers.append({"{#CONTROLLER_IP}": x['AgentXmppConnectionStatus']['peer']['list']['AgentXmppData']['controller_ip']['#text']})

        return json.dumps({"data": controllers})


def main(argv=sys.argv[1:]):
    cp = argparse.ArgumentParser(add_help=False)
    cp.add_argument('-H', '--host', type=str, default='127.0.0.1', help="Host to connect")
    cp.add_argument('-p', '--port', type=str, help='Port to connect')
    ap = argparse.ArgumentParser(description='Contrail Zabbix introspect monitor')
    sp = ap.add_subparsers(dest='resource', help='Resource to monitor')
    p_xmpp = sp.add_parser('xmpp', help='monitor xmpp introspect')
    sp_xmpp = p_xmpp.add_subparsers(dest='action')
    p_xmpp_detect = sp_xmpp.add_parser('detect', parents=[cp],
                                help="Detect xmpp controllers setup in vrouter agent")
    p_xmpp_monitor = sp_xmpp.add_parser('monitor', parents=[cp],
                                help="Monitor xmpp controllers setup in vrouter agent")

    p_xmpp_monitor.add_argument('controller_type', choices=['cfg_controller', 'mcast_controller'])
    p_xmpp_monitor.add_argument('--controller-ip', help="XMPP Controller IP to be monitored")

    p_bgp = sp.add_parser('bgp', help='monitor bgp introspect')
    sp_bgp = p_bgp.add_subparsers(dest='action')
    p_bgp_detect = sp_bgp.add_parser('detect', parents=[cp],
                                help="Detect bgp controllers setup in vrouter agent")
    p_bgp_monitor = sp_bgp.add_parser('monitor', parents=[cp],
                                help="Monitor bgp controllers setup in vrouter agent")
    p_bgp_monitor.add_argument('controller_ip', help="BGP Controller IP to be monitored")

    p_service_status = sp.add_parser('status', parents=[cp],
                                help="Monitor service status")

    p_service_status.add_argument('service_name', choices=[
        'schema', 'vrouter-agent', 'config-api', 'analytics-api', 'collector',
        'alarm-gen', 'control', 'discovery', 'dns', 'svc-monitor'])

    args = ap.parse_args()
    ir = IntrospectReader(args.host)

    OPS = {
        'xmpp': {
            'detect': 'xmpp_detect',
            'monitor': 'xmpp_status',
        },
        'bgp': {
            'detect': 'bgp_detect',
            'monitor': 'bgp_status',
        }
    }

    param_dict = {
        key: vars(args)[key]
        for key in vars(args) if key not in ['action', 'resource', 'host']
    }

    if args.resource == 'status':
        result = ir.node_status(args.service_name, port=args.port)
    else:
        result = getattr(ir, OPS[args.resource][args.action])(**param_dict)

    print result
    return True

if __name__ == "__main__":
    sys.exit(not main(sys.argv[1:]))
