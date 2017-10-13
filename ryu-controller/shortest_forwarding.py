import logging
import struct
import networkx as nx
from ipaddress import ip_address, ip_network
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmpv6
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

import network_awareness
import network_monitor
import network_delay_detector
import setting
import copy
import random



CONF = cfg.CONF


class ShortestForwarding(app_manager.RyuApp):
    """
        ShortestForwarding is a Ryu app for forwarding packets in shortest
        path.
        This App does not defined the path computation method.
        To get shortest path, this module depends on network awareness,
        network monitor and network delay detecttor modules.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_awareness": network_awareness.NetworkAwareness,
        "network_monitor": network_monitor.NetworkMonitor,
        "network_delay_detector": network_delay_detector.NetworkDelayDetector}

    WEIGHT_MODEL = {'hop': 'weight', 'delay': "delay", "bw": "bw"}

    def __init__(self, *args, **kwargs):
        super(ShortestForwarding, self).__init__(*args, **kwargs)
        self.name = 'shortest_forwarding'
        self.awareness = kwargs["network_awareness"]
        self.monitor = kwargs["network_monitor"]
        self.delay_detector = kwargs["network_delay_detector"]
        self.datapaths = {}
        self.weight = self.WEIGHT_MODEL[CONF.weight]
        self.port_mac_dic = {}
        self.send_ra_thread = hub.spawn_after(10, self.send_ra)

    def send_ra(self):
        while True:
            for dpid in self.port_mac_dic:
                for port in self.port_mac_dic[dpid]:
                    if 1 <= port <= 5:
                        datapath = self.datapaths[dpid]
                        parser = datapath.ofproto_parser
                        ofproto = datapath.ofproto 
                        ra_out = self.generate_ra_pkt(datapath, port)
                        ra_out.serialize()
                        data = ra_out.data
                        actions = [parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath,
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER,
                                                    actions=actions,
                                                    data=data)
                        datapath.send_msg(out)
            hub.sleep(300)

    def set_weight_mode(self, weight):
        """
            set weight mode of path calculating.
        """
        self.weight = weight
        if self.weight == self.WEIGHT_MODEL['hop']:
            self.awareness.get_shortest_paths(weight=self.weight)
        return True

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)
        
        

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        if flow_info[0] == 0x0800:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
        if flow_info[0] == 0x86DD:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv6_src=flow_info[1], ipv6_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=600, hard_timeout=1200)


    def send_transit_flow_mod(self, datapath, path, flow_info, transit_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match_action_dic = {}
        switch_tunnel_type = self.get_switch_tunnel_type(path, transit_info)
        ipv6_src = flow_info[1]
        ipv6_dst = flow_info[2]
        
        for transit_tech in transit_info[datapath.id]:
            actions_1 = []
            actions_2 = []
            actions_3 = []
            actions_4 = []
            if transit_tech == setting.NAT64_FlAG:
                match_1 = parser.OFPMatch(in_port=src_port, eth_type=0x86DD,ipv6_dst=flow_info[2])
                actions_1.append(parser.OFPActionSetField(eth_src=self.port_mac_dic[datapath.id][src_port]))
                actions_1.append(parser.OFPActionSetField(eth_dst=self.port_mac_dic[datapath.id][setting.NAT64_6_PORT_NO]))
                actions_1.append(parser.OFPActionDecNwTtl())
                actions_1.append(parser.OFPActionOutput(setting.NAT64_6_PORT_NO))
                match_action_dic.setdefault(match_1, actions_1)
                match_2 = parser.OFPMatch(in_port=setting.NAT64_4_PORT_NO, eth_type=0x0800,ipv4_src="192.0.2.129")
                actions_2.append(parser.OFPActionSetField(eth_src=self.port_mac_dic[datapath.id][setting.NAT64_4_PORT_NO]))
                actions_2.append(parser.OFPActionSetField(eth_dst="ff:ff:ff:ff:ff:ff"))
                actions_2.append(parser.OFPActionSetField(ipv4_src="10.0.1.2"))
                actions_2.append(parser.OFPActionDecNwTtl())
                actions_2.append(parser.OFPActionOutput(dst_port))
                match_action_dic.setdefault(match_2, actions_2)
                match_3 = parser.OFPMatch(in_port=dst_port, eth_type=0x0800,ipv4_dst="10.0.1.2")
                actions_3.append(parser.OFPActionSetField(eth_src=self.port_mac_dic[datapath.id][dst_port]))
                actions_3.append(parser.OFPActionSetField(eth_dst=self.port_mac_dic[datapath.id][setting.NAT64_4_PORT_NO]))
                actions_3.append(parser.OFPActionSetField(ipv4_dst="192.0.2.129"))
                actions_3.append(parser.OFPActionSetField(ip_dscp=4))
                actions_3.append(parser.OFPActionSetField(ip_ecn=2))
                actions_3.append(parser.OFPActionDecNwTtl())
                actions_3.append(parser.OFPActionOutput(setting.NAT64_4_PORT_NO))
                match_action_dic.setdefault(match_3, actions_3)
                match_4 = parser.OFPMatch(in_port=setting.NAT64_6_PORT_NO, eth_type=0x86DD, ipv6_src=('64:ff9b::', 'ffff:ffff:ffff:ffff:ffff:ffff::'))
                actions_4.append(parser.OFPActionSetField(eth_src=self.port_mac_dic[datapath.id][setting.NAT64_4_PORT_NO]))
                actions_4.append(parser.OFPActionSetField(eth_dst="33:33:00:00:00:01"))
                actions_4.append(parser.OFPActionDecNwTtl())
                actions_4.append(parser.OFPActionOutput(src_port))
                match_action_dic.setdefault(match_4, actions_4)
            if transit_tech == setting.V6OV4_FLAG:
                if switch_tunnel_type[datapath.id] == 'ce':
                    nw_src_port = src_port
                    nw_dst_port = dst_port
                    nw_ipv6_src = ipv6_dst
                    nw_ipv6_dst = ipv6_src
                if switch_tunnel_type[datapath.id] == 'br':
                    nw_src_port = dst_port
                    nw_dst_port = src_port
                    nw_ipv6_src = ipv6_src
                    nw_ipv6_dst = ipv6_dst
                match_1 = parser.OFPMatch(in_port=nw_src_port, eth_type=0x86DD)
                actions_1.append(parser.OFPActionSetField(eth_src=self.port_mac_dic[datapath.id][nw_src_port]))
                actions_1.append(parser.OFPActionSetField(eth_dst=self.port_mac_dic[datapath.id][setting.V6OV4_6_PORT_NO]))
                actions_1.append(parser.OFPActionDecNwTtl())
                actions_1.append(parser.OFPActionOutput(setting.V6OV4_6_PORT_NO))
                match_action_dic.setdefault(match_1, actions_1)
                match_2 = parser.OFPMatch(in_port=setting.V6OV4_4_PORT_NO, eth_type=0x0800)
                actions_2.append(parser.OFPActionSetField(ipv4_src="10.7.7.7"))
                actions_2.append(parser.OFPActionSetField(ipv4_dst="10.8.8.8"))
                actions_2.append(parser.OFPActionDecNwTtl())
                actions_2.append(parser.OFPActionOutput(nw_dst_port))
                match_action_dic.setdefault(match_2, actions_2)
                match_3 = parser.OFPMatch(in_port=nw_dst_port, eth_type=0x0800)
                actions_3.append(parser.OFPActionSetField(eth_dst=self.port_mac_dic[datapath.id][setting.V6OV4_4_PORT_NO]))
                actions_3.append(parser.OFPActionSetField(ipv4_src="192.0.2.2"))
                actions_3.append(parser.OFPActionSetField(ipv4_dst="192.0.2.1"))
                actions_3.append(parser.OFPActionDecNwTtl())
                actions_3.append(parser.OFPActionOutput(setting.V6OV4_4_PORT_NO))
                match_action_dic.setdefault(match_3, actions_3)
                match_4 = parser.OFPMatch(in_port=setting.V6OV4_6_PORT_NO, eth_type=0x86DD, ipv6_src=nw_ipv6_src, ipv6_dst=nw_ipv6_dst)
                actions_4.append(parser.OFPActionSetField(eth_src=self.port_mac_dic[datapath.id][nw_src_port]))
                actions_4.append(parser.OFPActionSetField(eth_dst="33:33:00:00:00:01"))
                actions_4.append(parser.OFPActionDecNwTtl())
                actions_4.append(parser.OFPActionOutput(nw_src_port))
                match_action_dic.setdefault(match_4, actions_4)
            if transit_tech == setting.V4OV6_FLAG:
                if switch_tunnel_type[datapath.id] == 'ce':
                    nw_src_port = src_port
                    nw_dst_port = dst_port
                if switch_tunnel_type[datapath.id] == 'br':
                    nw_src_port = dst_port
                    nw_dst_port = src_port
                match_1 = parser.OFPMatch(in_port=nw_src_port, eth_type=0x0800)
                actions_1.append(parser.OFPActionSetField(eth_dst=self.port_mac_dic[datapath.id][setting.V4OV6_4_PORT_NO]))
                actions_1.append(parser.OFPActionOutput(setting.V4OV6_4_PORT_NO))
                match_action_dic.setdefault(match_1, actions_1)
                match_2 = parser.OFPMatch(in_port=setting.V4OV6_6_PORT_NO, eth_type=0x86DD)
                actions_2.append(parser.OFPActionOutput(nw_dst_port))
                match_action_dic.setdefault(match_2, actions_2)
                match_3 = parser.OFPMatch(in_port=nw_dst_port, eth_type=0x86DD)
                actions_3.append(parser.OFPActionSetField(eth_dst=self.port_mac_dic[datapath.id][setting.V4OV6_6_PORT_NO]))
                actions_3.append(parser.OFPActionOutput(setting.V4OV6_6_PORT_NO))
                match_action_dic.setdefault(match_3, actions_3)
                match_4 = parser.OFPMatch(in_port=setting.V4OV6_4_PORT_NO, eth_type=0x0800)
                actions_4.append(parser.OFPActionOutput(nw_src_port))

        for match in match_action_dic:
            self.add_flow(datapath, 1, match, match_action_dic[match],
                      idle_timeout=600, hard_timeout=1200)
        if setting.V6OV4_FLAG in transit_info[datapath.id]:
            if switch_tunnel_type[datapath.id] == 'ce':
                nw_src_port = src_port
                nw_dst_port = dst_port
            if switch_tunnel_type[datapath.id] == 'br':
                nw_src_port = dst_port
                nw_dst_port = src_port
        #     # nw_match_1 = parser.OFPMatch(in_port=setting.V6OV4_6_PORT_NO, eth_type=0x86DD, ip_proto=58, icmpv6_type=135)
        #     # nw_actions_1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        #     # self.add_flow(datapath, 5, nw_match_1, nw_actions_1,
        #     #           idle_timeout=600, hard_timeout=1200)
            nw_match_2 = parser.OFPMatch(in_port=nw_src_port, eth_type=0x86DD, ip_proto=58, icmpv6_type=135)
            nw_actions_2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 5, nw_match_2, nw_actions_2,
                      idle_timeout=600, hard_timeout=1200)

    def get_switch_tunnel_type(self, path, transit_info):
        ce_flag = 0
        br_flag = 0
        switch_tunnel_type_dic = {}
        for dpid in path:
            for transit_type in transit_info[dpid]:
                if transit_type == setting.V6OV4_FLAG or transit_type == setting.V4OV6_FLAG:
                    if ce_flag == 0 and br_flag == 0:
                        switch_tunnel_type_dic.setdefault(dpid,'ce')
                        ce_flag = 1
                    elif ce_flag == 1 and br_flag == 0:
                        switch_tunnel_type_dic.setdefault(dpid,'br')
                        br_flag = 1
                    else:
                        switch_tunnel_type_dic.setdefault(dpid,'ce')
                        br_flag = 0
        return switch_tunnel_type_dic

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if ip_address(dst_ip) in ip_network("64:ff9b::/96"):
            return 1
        
        if access_table:
            if isinstance(list(access_table.values())[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        for dpid in setting.Network_dic:
            for port in setting.Network_dic[dpid]:
                if ip_address(dst_ip) in ip_network(setting.Network_dic[dpid][port]):
                    return port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                             src_dpid, dst_dpid))
            return None

    def arp_flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.awareness.access_ports:
            for port in self.awareness.access_ports[dpid]:
                if (dpid, port) not in self.awareness.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def nd_flood(self, msg):
        """
            Flood ICMPv6ND packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)

        for dpid in self.awareness.access_ports:
            for port in self.awareness.access_ports[dpid]:
                if (dpid, port) not in self.awareness.ipv6_access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
                else:
                    if ip_address(pkt[1].dst).is_multicast:
                        datapath = self.datapaths[dpid]
                        out = self._build_packet_out(
                            datapath, ofproto.OFP_NO_BUFFER,
                            ofproto.OFPP_CONTROLLER, port, msg.data)
                        datapath.send_msg(out)

        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.awareness.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.arp_flood(msg)

    def icmpv6nd_forwarding(self, msg, src_ip, dst_ip):
        """ Send icmpv6nd packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        result = self.awareness.get_ipv6_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                        ofproto.OFPP_CONTROLLER,
                                        out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Reply ICMPv6NS to knew host")
        else:
            self.nd_flood(msg)

    def get_path(self, dp, port, src, dst, weight):
        """
            Get shortest path from network awareness module.
        """
        shortest_paths = self.awareness.shortest_paths
        graph = self.awareness.graph
        possible_paths = self.awareness.possible_paths

        if weight == self.WEIGHT_MODEL['hop']:
            return shortest_paths.get(src).get(dst)[0]
        elif weight == self.WEIGHT_MODEL['delay']:
            # If paths existed, return it, else calculate it and save it.
            try:
                paths = shortest_paths.get(src).get(dst)
                return paths[0]
            except:
                paths = self.awareness.k_shortest_paths(graph, src, dst,
                                                        weight=weight)

                shortest_paths.setdefault(src, {})
                shortest_paths[src].setdefault(dst, paths)
                return paths[0]
        elif weight == self.WEIGHT_MODEL['bw']:
            # Because all paths will be calculate
            # when call self.monitor.get_best_path_by_bw
            # So we just need to call it once in a period,
            # and then, we can get path directly.
            try:
                # if path is existed, return it.
                path = self.monitor.best_paths.get(src).get(dst)
                return path
                #if self.monitor.check_create_flag(graph,possible_paths,src,dst) and self.monitor.check_traffic_flag(dp.id,port, self.monitor.current_traffic):                                     
                    #path = self.monitor.port_path_dic.get(dp.id).get(port)
                    #return path
            except:
                # else, calculate it, and return.
                
                result = self.monitor.get_best_path_by_bw(graph, shortest_paths)
                #if self.monitor.check_create_flag(graph,possible_paths,src,dst) and self.monitor.check_traffic_flag(dp.id,port, self.monitor.current_traffic):                                     
                    #result = self.monitor.get_best_path_by_te(dp, port, graph, src, dst, possible_paths)
                    
                    #best_path = result.get(dp.id).get(port)
                paths = result[1]
                best_path = paths.get(src).get(dst)
                return best_path
    
    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None
        src_location = None
        dst_location = None
        if ip_address(src).version == 4:
            src_location = self.awareness.get_host_location(src)
        if ip_address(src).version == 6 and not ip_address(src).is_link_local:
            src_location = self.awareness.get_ipv6_host_location(src)
        if in_port in self.awareness.access_ports[dpid]:
            if [dpid, in_port] == src_location or (dpid, in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None
        if ip_address(src).version == 4:
            dst_location = self.awareness.get_host_location(dst)
        if ip_address(src).version == 6 and not ip_address(src).is_link_local:
            dst_location = self.awareness.get_ipv6_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]
        else:
            if ip_address(dst) in ip_network("64:ff9b::/96"):
                dst_sw = 1016511457371
        
        return src_sw, dst_sw

    def install_flow(self, datapaths, link_to_port, access_table, path,
                     flow_info, transit_info, buffer_id, data=None):
        ''' 
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # inter_link
        if len(path) > 2:
            for i in range(1, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    if transit_info[path[i]]:
                        self.send_transit_flow_mod(datapath, path, flow_info, transit_info, src_port, dst_port)
                    else:
                        self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                        self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    self.logger.debug("inter_link flow install")
        if len(path) > 1:
            # the last flow entry: tor -> host
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1]

            dst_port = self.get_port(flow_info[2], access_table)
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return

            last_dp = datapaths[path[-1]]
            if transit_info[path[-1]]:
                self.send_transit_flow_mod(last_dp, path, flow_info, transit_info, src_port, dst_port)
            else:
                self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
                self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # the first flow entry
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0]
            if transit_info[path[0]]:
                self.send_transit_flow_mod(first_dp, path, flow_info, transit_info, in_port, out_port)
            else:
                self.send_flow_mod(first_dp, flow_info, in_port, out_port)
                self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        # src and dst on the same datapath
        else:
            out_port = self.get_port(flow_info[2], access_table)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            if path[0] in transit_info:
                self.send_transit_flow_mod(last_dp, path, flow_info, transit_info, in_port, out_port)
            else: 
                pass
                #self.send_flow_mod(first_dp, flow_info, in_port, out_port)
                #self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    def change_index(self, path):
        index_changed_path = copy.deepcopy(path)
        for i in range(len(path)):
            if path[i] == 830366948081:
                index_changed_path[i] = 1
            if path[i] == 1016511457371:
                index_changed_path[i] = 2
        return index_changed_path

    def get_transit_info(self, path, ip_src, ip_dst):
        """
            get transit information 
        """
        link_type_mx = setting.LINK_TYPE
        path_node_tran_dic = {}
        tran_list = []
        tr_flag = 0
        nw_path = self.change_index(path)
        if ip_address(ip_src).version == 6 and ip_address(ip_src).version == 6:
            if ip_address(ip_dst) in ip_network("64:ff9b::/96"):
                for i in range(len(path)-1):
                    path_node_tran_dic.setdefault(path[i],[])
                    path_node_tran_dic.setdefault(path[i+1],[])
                    if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 6 and tr_flag == 0:
                        pass
                    if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 4 and tr_flag == 0: 
                        tran_list.append(setting.NAT64_FlAG)
                        for j in tran_list:
                            path_node_tran_dic[path[i]].append(j)
                        tr_flag = 1
                    if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 6 and tr_flag == 1:
                        tran_list.append(setting.V4OV6_FLAG)
                        for j in tran_list:
                            path_node_tran_dic[path[i]].append(j)
                        if path_node_tran_dic[path[i+1]] is None:
                            path_node_tran_dic.setdefault(path[i+1],[])
                            for j in tran_list:
                                path_node_tran_dic[path[i+1]].append(j)
                        else:
                            for j in tran_list:
                                path_node_tran_dic[path[i+1]].append(j)
                    if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 4 and tr_flag == 1:
                        pass
                    tran_list = []
            else:
                for i in range(len(path)-1):
                    path_node_tran_dic.setdefault(path[i],[])
                    path_node_tran_dic.setdefault(path[i+1],[])
                    if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 6:
                        pass
                    if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 4:
                        tran_list.append(setting.V6OV4_FLAG)
                        for j in tran_list:
                            path_node_tran_dic[path[i]].append(j)
                        if path_node_tran_dic[path[i+1]] is None:
                            path_node_tran_dic.setdefault(path[i+1],[])
                            for j in tran_list:
                                path_node_tran_dic[path[i+1]].append(j)
                        else:
                            for j in tran_list:
                                path_node_tran_dic[path[i+1]].append(j)
                    tran_list = []
        if ip_address(ip_src).version == 4 and ip_address(ip_src).version == 4:
            for i in range(len(path)-1):
                path_node_tran_dic.setdefault(path[i],[])
                path_node_tran_dic.setdefault(path[i+1],[])
                if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 4:
                    pass
                if link_type_mx[nw_path[i]-1][nw_path[i+1]-1] == 6:
                    tran_list.append(setting.V4OV6_FLAG)
                    for j in tran_list:
                        path_node_tran_dic[path[i]].append(j)
                    if path_node_tran_dic[path[i+1]] is None:
                        path_node_tran_dic.setdefault(path[i+1],[])
                        for j in tran_list:
                            path_node_tran_dic[path[i+1]].append(j)
                    else:
                        for j in tran_list:
                            path_node_tran_dic[path[i+1]].append(j)
                tran_list = []
        return path_node_tran_dic

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            To calculate shortest forwarding path and install them into datapaths.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        print("-----------------------short")
        print(ip_dst)
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        print(result)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # Path has already calculated, just get it.
                path = self.get_path(datapath, in_port, src_sw, dst_sw, weight=self.weight)
                if path is not None:
                    print(datapath.id)
                    print(in_port)
                    print(result)
                    self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                    transit_info = self.get_transit_info(path, ip_src, ip_dst)
                    flow_info = (eth_type, ip_src, ip_dst, in_port)
                    # install flow entries to datapath along side the path.
                    if ip_address(ip_src).version == 4: 
                        self.install_flow(self.datapaths,
                                        self.awareness.link_to_port,
                                        self.awareness.access_table, path,
                                        flow_info, transit_info, msg.buffer_id, msg.data)
                    if ip_address(ip_src).version == 6: 
                        self.install_flow(self.datapaths,
                                        self.awareness.link_to_port,
                                        self.awareness.ipv6_access_table, path,
                                        flow_info, transit_info, msg.buffer_id, msg.data)
                
        return

    def generate_ra_pkt(self, datapath, in_port):
        nd_option_sla = icmpv6.nd_option_sla(hw_src=self.port_mac_dic[datapath.id][in_port])
        nd_option_pi = icmpv6.nd_option_pi(
            pl=64, res1=6, val_l=2592000, pre_l=604800,
            prefix=setting.Prefix_dic[datapath.id][in_port])
        ra_data = icmpv6.nd_router_advert(ch_l=64, res=0, rou_l=1800, rea_t=0, ret_t=0,
                                        options=[nd_option_sla, nd_option_pi])
        ra_pkt = packet.Packet()
        ra_pkt.add_protocol(ethernet.ethernet(ethertype=0x86DD, dst='33:33:00:00:00:01', src=self.port_mac_dic[datapath.id][in_port]))
        ra_pkt.add_protocol(ipv6.ipv6(dst='ff02::1', src=setting.Port_link_dic[datapath.id][in_port], nxt=58))
        ra_pkt.add_protocol(icmpv6.icmpv6(type_=134, code=0, data=ra_data))
        return ra_pkt

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id

        for p in ev.msg.body:
            self.port_mac_dic.setdefault(dpid, {})
            self.port_mac_dic[dpid][p.port_no] = p.hw_addr
    
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.error('ERROR from %016x type=%d,code=%d', msg.datapath.id, msg.type, msg.code)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP.
            Therefore, the first packet from UNKOWN host MUST be ARP.
        '''
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        no_thing = 0

        # print("!!!!!!!!!!!!!!!!!!!!!!!!")
        # print(self.port_mac_dic)
        # print(self.awareness.ipv6_access_table)

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            if 6 <= in_port <= 11:
                eth_src = '02'
                for i in range(0, 5):
                    r = random.randint(0, 255)
                    s = ':' + ('00' + hex(r)[2:])[-2:]
                    eth_src += s
                match = parser.OFPMatch(in_port=in_port, eth_type=0x806, arp_op=1)
                actions =  [parser.OFPActionSetField(eth_src=eth_src),
                            parser.OFPActionSetField(eth_dst=pkt[0].src),
                            parser.OFPActionSetField(arp_op=2),
                            parser.OFPActionSetField(arp_spa=pkt[1].dst_ip),
                            parser.OFPActionSetField(arp_tpa=pkt[1].src_ip),
                            parser.OFPActionSetField(arp_sha=eth_src),
                            parser.OFPActionSetField(arp_tha=pkt[1].src_mac),
                            parser.OFPActionOutput(port=ofproto.OFPP_IN_PORT)]
                self.add_flow(datapath, 1, match, actions,
                      idle_timeout=600, hard_timeout=1200)
            else:    
                self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)
       
        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ipv4_pkt.src, ipv4_pkt.dst)

        if isinstance(ipv6_pkt, ipv6.ipv6):
            self.logger.debug("IPV6 processing")
            if len(pkt.get_protocols(ethernet.ethernet)):
                if len(pkt) == 3 and 133 <= pkt[2].type_ <= 137:
                    self.logger.debug("ICMPv6 processing")
                    if pkt[2].type_ == 133:
                        ra_pkt = self.generate_ra_pkt(datapath, in_port)
                        ra_pkt.serialize()
                        data = ra_pkt.data
                        actions = [parser.OFPActionOutput(port=in_port)]
                        out = parser.OFPPacketOut(datapath=datapath,
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER,
                                                    actions=actions,
                                                    data=data)
                        datapath.send_msg(out)
                    
                    #if ip_address(pkt[2].data.dst) in ip_network("64:ff9b::/96"):
                    if pkt[2].type_ == 135:
                        eth_src = self.port_mac_dic[datapath.id][in_port]
                        #eth_src = "50:af:73:24:48:b1" 
                        nd_data_recv = pkt[2].data
                        assert isinstance(nd_data_recv, icmpv6.nd_neighbor)
                        target_addr = nd_data_recv.dst
                        nd_option_tla = icmpv6.nd_option_tla(hw_src=eth_src)
                        na_data = icmpv6.nd_neighbor(res=6, dst=target_addr, option=nd_option_tla)
                        na_pkt = packet.Packet()
                        na_pkt.add_protocol(ethernet.ethernet(ethertype=0x86DD, dst=pkt[0].src, src=eth_src))
                        na_pkt.add_protocol(ipv6.ipv6(dst=pkt[1].src, src=setting.Port_link_dic[datapath.id][in_port], nxt=58))
                        na_pkt.add_protocol(icmpv6.icmpv6(type_=136, code=0, data=na_data))
                        na_pkt.serialize()
                        data = na_pkt.data
                        actions = [parser.OFPActionOutput(port=in_port)]
                        out = parser.OFPPacketOut(datapath=datapath,
                                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                                    in_port=ofproto.OFPP_CONTROLLER,
                                                    actions=actions,
                                                    data=data)
                        datapath.send_msg(out)    
                        #self.icmpv6nd_forwarding(msg, pkt[1].src, pkt[1].dst)
                    
                else:
                    if ip_address(ipv6_pkt.dst) != ip_address('2001:da8:202:10::36'):
                        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                        self.shortest_forwarding(msg, eth_type, ipv6_pkt.src, ipv6_pkt.dst)