import numpy as np
DISCOVERY_PERIOD = 10   			# For discovering topology.

MONITOR_PERIOD = 10					# For monitoring traffic

DELAY_DETECTING_PERIOD = 5			# For detecting link delay.

TOSHOW = True						# For showing information in terminal
	
MAX_CAPACITY = 281474976710655		# Max capacity of link

METRIC_FLAG = 0

ESP = 0.0000000000000000000001

TRAFFIC_FLAG = 4

NAT64_FlAG = 1
V6OV4_FLAG = 2
V4OV6_FLAG = 3

NAT64_6_PORT_NO = 6
NAT64_4_PORT_NO = 7
V6OV4_6_PORT_NO = 8
V6OV4_4_PORT_NO = 9
V4OV6_6_PORT_NO = 11
V4OV6_4_PORT_NO = 10

LINK_TYPE = np.array(
    [
        [0,4],
        [0,0]
    ]
)

Port_link_dic = {830366948081:{1:'fe80::2c1:55ff:feba:1af1', 8:'fe80::6c08:b6ff:fe67:a9f3'}, 
                    1016511457371:{1:'fe80::2ec:acff:fecd:e85b', 8:'fe80::b041:3eff:fe88:4108'}}

Prefix_dic = {830366948081:{1:'2001:1234::'}, 
                    1016511457371:{1:'2001:5678::'}}
Network_dic = {830366948081:{1:'2001:1234::/64'}, 
                    1016511457371:{1:'2001:5678::/64'}}

# LINK_TYPE = np.array(
#     [
#         [0,6,6,6,0,0,0],
#         [0,0,0,0,0,0,6],
#         [0,0,0,0,6,0,0],
#         [0,0,0,0,0,6,0],
#         [0,0,0,0,0,0,6],
#         [0,0,0,0,0,0,6],
#         [0,0,0,0,0,0,0]
#     ]
# )                                   # IP type metric of link
