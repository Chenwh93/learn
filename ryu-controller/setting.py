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

NAT64_6_PORT_NO = 1
NAT64_4_PORT_NO = 2
V6OV4_6_PORT_NO = 3
V6OV4_4_PORT_NO = 4
V4OV6_6_PORT_NO = 5
V4OV6_4_PORT_NO = 6

LINK_TYPE = np.array(
    [
        [0,4,4,4,0,0,0],
        [0,0,0,0,0,0,4],
        [0,0,0,0,4,0,0],
        [0,0,0,0,0,6,0],
        [0,0,0,0,0,0,4],
        [0,0,0,0,0,0,4],
        [0,0,0,0,0,0,0]
    ]
)                                   # IP type metric of link
