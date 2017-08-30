from __future__ import division
import copy
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
import setting
import networkx as nx
import numpy as np
import os


CONF = cfg.CONF


class NetworkMonitor(app_manager.RyuApp):
    """
        NetworkMonitor is a Ryu app for collecting traffic information.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkMonitor, self).__init__(*args, **kwargs)
        self.name = 'monitor'
        self.datapaths = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.stats = {}
        self.port_features = {}
        self.free_bandwidth = {}
        self.current_traffic = {}
        self.awareness = lookup_service_brick('awareness')
        self.graph = None
        self.capabilities = None
        self.best_paths = None
        self.port_path_dic = None
        self.init_capabilities_metric = None
        # Start to green thread to monitor traffic and calculating
        # free bandwidth of links respectively.
        self.monitor_thread = hub.spawn(self._monitor)
        self.save_freebandwidth_thread = hub.spawn(self._save_bw_graph)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Record datapath's info
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

    def _monitor(self):
        """
            Main entry method of monitoring traffic.
        """
        while CONF.weight == 'bw':
            self.stats['flow'] = {}
            self.stats['port'] = {}
            for dp in self.datapaths.values():
                self.port_features.setdefault(dp.id, {})
                self._request_stats(dp)
                # refresh data.
                self.capabilities = None
                self.best_paths = None
                #self.port_path_dic = None
            hub.sleep(setting.MONITOR_PERIOD)
            if self.stats['flow'] or self.stats['port']:
                #self.show_stat('flow')
                #self.show_stat('port')
                hub.sleep(1)

    def _save_bw_graph(self):
        """
            Save bandwidth data into networkx graph object.
        """
        while CONF.weight == 'bw':
            self.graph = self.create_bw_graph(self.free_bandwidth)                
            self.logger.debug("save_freebandwidth")
            hub.sleep(setting.MONITOR_PERIOD)

    
    def create_capabilities_metric(self, graph):
        """
            Convert bandwidth graph into metric.
        """
        capabilities_metric = nx.to_numpy_matrix(graph, weight='bandwidth')
        capabilities_metric_t = np.zeros([len(capabilities_metric), len(capabilities_metric)])
        for i in range(capabilities_metric.shape[0]):
            for j in range(capabilities_metric.shape[1]):
                if i == j:
                    capabilities_metric[i,j] = 0
        for i in range(capabilities_metric.shape[0]):
            for j in range(capabilities_metric.shape[1]):
                if capabilities_metric[i,j] == 0:
                    capabilities_metric_t[i,j] = capabilities_metric[i,j] + setting.ESP
                else:
                    capabilities_metric_t[i, j] = capabilities_metric[i, j]
        return capabilities_metric_t

    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def get_min_bw_of_links(self, graph, path, min_bw):
        """
            Getting bandwidth of path. Actually, the mininum bandwidth
            of links is the bandwith, because it is the neck bottle of path.
        """
        _len = len(path)
        if _len > 1:
            minimal_band_width = min_bw
            for i in range(_len-1):
                pre, curr = path[i], path[i+1]
                if 'bandwidth' in graph[pre][curr]:
                    bw = graph[pre][curr]['bandwidth']
                    minimal_band_width = min(bw, minimal_band_width)
                else:
                    continue
            return minimal_band_width
        return min_bw

    def check_create_flag(self, graph, paths, src, dst):
        create_flag = False
        for path in paths[src][dst]:
            _len = len(path)
            if _len > 1:
                for i in range(_len-1):
                    if 'bandwidth' in graph[path[i]][path[i+1]]:
                        if graph[path[i]][path[i+1]]['bandwidth'] > 1000:
                            create_flag = True
        return create_flag      

    def check_traffic_flag(self, dp, port, traffic_metric):
        traffic_flag = False
        if traffic_metric[dp][port] >= setting.TRAFFIC_FLAG:
            traffic_flag = True
        return traffic_flag 

    def get_demand_traffic(self, dp, traffic_metric):
        demand_traffic = {}
        for dpid in traffic_metric:
            if dpid == dp.id:
                demand_traffic.setdefault(dpid, {})
                for port_no in traffic_metric[dpid]:
                    if traffic_metric[dpid][port_no] > 1:
                        demand_traffic[dpid].setdefault(port_no, None)
                        demand_traffic[dpid][port_no] = traffic_metric[dpid][port_no]
        return demand_traffic

    def get_max_utilization(self, path, traffic, cp_metric):
        max_utilization = 0
        utilization = np.zeros([1,len(path)-1])
        for i in range(len(path)-1):
            utilization[0,i] = traffic / (cp_metric[path[i]-1,path[i+1]-1] / 1000)
        max_utilization = np.amax(utilization)
        return max_utilization

    def get_weight_metric(self, cp_metric):
        weight_metric = 1 / (cp_metric / 1000)
        return weight_metric
           
    def get_best_path_by_te(self, dp, port, graph, src, dst, paths):
        port_path_dic = {}
        d = 0        
        create_flag = self.check_create_flag(graph, paths, src, dst)
        traffic_flag = self.check_traffic_flag(dp.id, port, self.current_traffic)
        if create_flag and traffic_flag:
            new_graph = self.change_graph_weight_by_bw(graph)
            traffic_mx = copy.deepcopy(self.current_traffic)
            capability_mx = self.create_capabilities_metric(graph)
            weight_mx = self.get_weight_metric(capability_mx) 
            demand_traffic = self.get_demand_traffic(dp, traffic_mx)
            for dpid in demand_traffic:
                for port_no in demand_traffic[dpid]:
                    d = d + demand_traffic[dpid][port_no]
            occupy_metric = np.zeros([len(capability_mx), len(capability_mx)])
            while d > 0:
                tmp_dpid = None
                tmp_port_no = None
                traffic = 0
                best_path = nx.dijkstra_path(new_graph,src,dst)
                access_metric = capability_mx - occupy_metric
                c = self.get_min_bw_of_links(graph, best_path, setting.MAX_CAPACITY) / 1000
                p_t = self.get_max_utilization(best_path, d, capability_mx)
                p = max(1, p_t)
                f = min(c, d)
                for dpid in demand_traffic:
                    for port_no in demand_traffic[dpid]:
                        if demand_traffic[dpid][port_no] <= f/p:
                            traffic = demand_traffic[dpid][port_no]
                            tmp_dpid = dpid
                            tmp_port_no = port_no
                            del demand_traffic[dpid][port_no]
                            break
                for j in range(len(best_path)-1):
                    occupy_metric[best_path[j]-1][best_path[j+1]-1] = occupy_metric[best_path[j]-1][best_path[j+1]-1] + traffic
                d = d - traffic
                
                for k in range(len(best_path)-1):
                    weight_mx[best_path[k]-1][best_path[k+1]-1] = weight_mx[best_path[k]-1][best_path[k+1]-1] * (1 + d / (capability_mx[best_path[k]-1][best_path[k+1]-1]/1000))
                    new_graph[best_path[k]][best_path[k+1]]['weight'] = weight_mx[best_path[k]-1][best_path[k+1]-1]
                
                port_path_dic.setdefault(tmp_dpid, {})
                port_path_dic[tmp_dpid].setdefault(tmp_port_no, None)
                port_path_dic[tmp_dpid][tmp_port_no] = best_path
                        
            #print('---!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!---')
            #print(port_path_dic)             
            #print('---!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!---')
            #os._exit(0)
        self.port_path_dic = port_path_dic
        return port_path_dic
            


    def change_graph_weight_by_bw(self, graph): 
        cp_metric = self.create_capabilities_metric(graph)
        tmp_graph = nx.DiGraph()
        weight_metric = 1 / (cp_metric / 1000)
        for i in range(len(weight_metric)):
            for j in range(len(weight_metric[0])):
                tmp_graph.add_edge(i+1,j+1,weight=weight_metric[i,j])
        
        return tmp_graph

    def get_best_path_by_bw(self, graph, paths):
        """
            Get best path by comparing paths.
        """
        capabilities = {}
        best_paths = copy.deepcopy(paths)
        for src in paths:
            for dst in paths[src]:
                if src == dst:
                    best_paths[src][src] = [src]
                    capabilities.setdefault(src, {src: setting.MAX_CAPACITY})
                    capabilities[src][src] = setting.MAX_CAPACITY
                    continue
                max_bw_of_paths = 0
                best_path = paths[src][dst][0]
                for path in paths[src][dst]:
                    min_bw = setting.MAX_CAPACITY
                    min_bw = self.get_min_bw_of_links(graph, path, min_bw)
                    if min_bw > max_bw_of_paths:
                        max_bw_of_paths = min_bw
                        best_path = path

                best_paths[src][dst] = best_path
                capabilities.setdefault(src, {dst: max_bw_of_paths})
                capabilities[src][dst] = max_bw_of_paths
        self.capabilities = capabilities
        self.best_paths = best_paths
        
        return capabilities, best_paths

    def create_bw_graph(self, bw_dict):
        """
            Save bandwidth data into networkx graph object.
        """
        try:
            graph = self.awareness.graph
            link_to_port = self.awareness.link_to_port
            for link in link_to_port:
                (src_dpid, dst_dpid) = link
                (src_port, dst_port) = link_to_port[link]
                if src_dpid in bw_dict and dst_dpid in bw_dict:
                    bw_src = bw_dict[src_dpid][src_port]
                    bw_dst = bw_dict[dst_dpid][dst_port]
                    bandwidth = min(bw_src, bw_dst)
                    # add key:value of bandwidth into graph.
                    graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
                else:
                    graph[src_dpid][dst_dpid]['bandwidth'] = 0
            return graph
        except:
            self.logger.info("Create bw graph exception")
            if self.awareness is None:
                self.awareness = lookup_service_brick('awareness')
            return self.awareness.graph

    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
        else:
            self.logger.info("Fail in getting port state")
    
    def _get_current_traffic(self,dpid, port_no, speed):
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            curr_tr = speed * 8/10**6
            self.current_traffic[dpid].setdefault(port_no, None)
            self.current_traffic[dpid][port_no] = curr_tr
        else:
            self.logger.info("Fail in getting port state")

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
        return max(capacity/10**3 - speed * 8/10**6, 0)

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match.get('in_port'),
                                             flow.match.get('ipv4_dst'))):
            key = (stat.match['in_port'],  stat.match.get('ipv4_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            period = setting.MONITOR_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})
        self.current_traffic.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = setting.MONITOR_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)
                self._get_current_traffic(dpid, port_no, speed)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        if reason in reason_dict:

            print ("switch%d: port %s %s" % (dpid, reason_dict[reason], port_no))
        else:
            print ("switch%d: Illeagal port state %s %s" % (port_no, reason))

    def show_stat(self, type):
        '''
            Show statistics info according to data type.
            type: 'port' 'flow'
        '''
        if setting.TOSHOW is False:
            return

        bodys = self.stats[type]
        """
        print('---!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!---')
        for n,nbrs in self.awareness.graph.adjacency_iter():
            for nbr,eattr in nbrs.items():
                if 'weight' in eattr and 'bandwidth' in eattr:
                
                    print('(%d, %d, %d, %d)' % (n,nbr,eattr['weight'],eattr['bandwidth']))
        print('---!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!---')
        #A = nx.to_numpy_matrix(self.awareness.graph, weight='bandwidth')
        #print(A)
        #print('---!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!---')
        print(self.init_capabilities_metric)
        print('---!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!---')
        """
        
        if(type == 'flow'):
            print('datapath         ''   in-port        ip-dst      '
                  'out-port packets  bytes  flow-speed(B/s)')
            print('---------------- ''  -------- ----------------- '
                  '-------- -------- -------- -----------')
            for dpid in bodys.keys():
                for stat in sorted(
                    [flow for flow in bodys[dpid] if flow.priority == 1],
                    key=lambda flow: (flow.match.get('in_port'),
                                      flow.match.get('ipv4_dst'))):
                    print('%016x %8x %17s %8x %8d %8d %8.1f' % (
                        dpid,
                        stat.match['in_port'], stat.match['ipv4_dst'],
                        stat.instructions[0].actions[0].port,
                        stat.packet_count, stat.byte_count,
                        abs(self.flow_speed[dpid][
                            (stat.match.get('in_port'),
                            stat.match.get('ipv4_dst'),
                            stat.instructions[0].actions[0].port)][-1])))
            print ('\n')

        if(type == 'port'):
            print('datapath             port   ''rx-pkts  rx-bytes rx-error '
                  'tx-pkts  tx-bytes tx-error  port-speed(B/s)'
                  ' current-capacity(Kbps)  '
                  'port-stat   link-stat')
            print('----------------   -------- ''-------- -------- -------- '
                  '-------- -------- -------- '
                  '----------------  ----------------   '
                  '   -----------    -----------')
            format = '%016x %8x %8d %8d %8d %8d %8d %8d %8.1f %16d %16s %16s'
            for dpid in bodys.keys():
                for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                    if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                        print(format % (
                            dpid, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                            abs(self.port_speed[(dpid, stat.port_no)][-1]),
                            self.port_features[dpid][stat.port_no][2],
                            self.port_features[dpid][stat.port_no][0],
                            self.port_features[dpid][stat.port_no][1]))
            print ('\n')