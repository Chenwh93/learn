import networkx as nx
import numpy as np
import matplotlib.pyplot as plt

def find_max(a,b):
    if a > b:
        return a
    else:
        return b

def find_min(a,b):
    if a < b:
        return a
    else:
        return b

def te(C_orig,O_orig,traffic,link_type):
    DL = 0
    G = nx.Graph()
    Rud = np.zeros([2,2])
    Tud = np.array(
        [
            [1,0],
            [0,0]
        ]
    )

    O1 = np.zeros([len(O_orig), len(O_orig)])
    O2 = np.zeros([len(O_orig), len(O_orig)])
    O3 = np.zeros([len(O_orig), len(O_orig)])
    O4 = np.zeros([len(O_orig), len(O_orig)])

    while DL < 1:
        for m in range(len(traffic)):
            d = traffic[m][0]
            src = traffic[m][1]
            dst = traffic[m][2]
            src_type = traffic[m][3]
            dst_type = traffic[m][4]

            if src_type == 6 and dst_type == 6:
                pass
            if src_type == 6 and dst_type == 4:
                pass
            if src_type == 4 and dst_type == 4:
                C = selectroute(C_orig,link_type,src,dst,src_type,dst_type)
                C_T = np.zeros([len(C), len(C)])
                for i in range(len(C)):
                    for j in range(len(C[0])):
                        if C[i,j] == 0:
                            C_T[i,j] = C[i,j] + M
                        else:
                            C_T[i, j] = C[i, j]
                W = 0.000001 / C_T
                O = O3
                for i in range(len(W)):
                    for j in range(len(W[0])):
                        if W[i,j] <= 100000:
                            G.add_edge(i, j, weight=W[i,j])
            if src_type == 4 and dst_type == 6:
                pass

            while DL < 1 and d > 0:
                path = nx.dijkstra_path(G,src,dst)
                bandwidth = np.zeros([1,len(path)-1])
                utilization = np.zeros([1,len(path)-1])
                AT = C_orig - O_orig
                A = C - O
                for i in range(len(path)-1):
                    bandwidth[0,i] = find_min(A[path[i]][path[i+1]],AT[path[i]][path[i+1]])
                    #bandwidth[0,i] = A[path[i],path[i+1]]
                    utilization[0,i] = d / C[path[i],path[i+1]]
                c = np.amin(bandwidth)
                p_t = np.amax(utilization)
                p = find_max(1, p_t)
                f = find_min(c,d)

                for j in range(len(path)-1):
                    O[path[j]][path[j+1]] = O[path[j]][path[j+1]] + f/p
                    O_orig[path[j]][path[j+1]] = O_orig[path[j]][path[j+1]] + f/p

                d = d - f/p
                if src == 0 and dst == 6:
                    Rud[0][0] = Rud[0][0] + f/p

                for k in range(len(path)-1):
                    W[path[k]][path[k+1]] = W[path[k]][path[k+1]] * (1 + d/C[path[k]][path[k+1]])
                    G[path[k]][path[k+1]]['weight'] = W[path[k]][path[k+1]]

                S = C*W
                DL = S.sum()
            if src_type == 6 and dst_type == 6:
                O1 = O
            if src_type == 6 and dst_type == 4:
                O2 = O
            if src_type == 4 and dst_type == 4:
                O3 = O
            if src_type == 4 and dst_type == 6:
                O4 = O

    print(Rud)
    print(Tud)
    TudT = np.zeros([2,2])
    for i in range(len(Tud)):
        for j in range(len(Tud[0])):
            if Tud[i,j] == 0:
                TudT[i,j] = Tud[i,j] + M
            else:
                TudT[i, j] = Tud[i, j]
    tmp = Rud/np.linalg.inv(TudT)
    tmpT = np.zeros([2,2])
    for i in range(len(tmp)):
        for j in range(len(tmp[0])):
            if tmp[i,j] == 0:
                tmpT[i,j] = tmp[i,j] + M_b
            else:
                tmpT[i, j] = tmp[i, j]
    lamda = tmpT.min()
    throughput = (lamda*Tud).sum()
    return throughput

def selectroute(C,link_type_metric,src,dst,src_type,dst_type):
    C_out = np.zeros([7,7])
    G = nx.Graph()
    CT = np.zeros([len(C), len(C)])
    for i in range(len(C)):
        for j in range(len(C[0])):
            if C[i,j] == 0:
                CT[i,j] = C[i,j] + M
            else:
                CT[i, j] = C[i, j]
    W = 0.000001 / CT

    for i in range(len(W)):
        for j in range(len(W[0])):
            if W[i,j] <= 1000000:
                G.add_edge(i, j, weight=W[i,j])

    possiblePaths = nx.all_simple_paths(G,src,dst)
    
    for path in possiblePaths:
        tu_num = 0
        tr_num = 0
        as_Path = []
        tr_flag = 0
        if src_type == 6 and dst_type == 6:
            pass
        elif src_type == 6 and dst_type == 4:
            pass
        elif src_type == 4 and dst_type == 4:
            for j in range(len(path)-1):
                if link_type_metric[path[j]][path[j+1]] == 6:
                    tmpP = [9.8,path[j],path[j+1]]
                    tu_num = tu_num + 1
                elif link_type_metric[path[j]][path[j+1]] == 4:
                    tmpP = [10,path[j],path[j+1]]
                as_Path.append(tmpP)
            if tu_num < 3:
                for k in range(len(as_Path)):
                    C_out[as_Path[k][1]][as_Path[k][2]] = as_Path[k][0]
        elif src_type == 4 and dst_type == 6:
            pass

    return C_out

M = 0.0000000000000000000001
M_b = 9999999999999
C0 = np.array(
    [
        [0,10,10,10,0,0,0],
        [0,0,0,0,0,0,10],
        [0,0,0,0,10,0,0],
        [0,0,0,0,0,10,0],
        [0,0,0,0,0,0,10],
        [0,0,0,0,0,0,10],
        [0,0,0,0,0,0,0]
    ]
)

C3 = np.array(
    [
        [0,10,10,10,0,0,0],
        [0,0,0,0,0,0,10],
        [0,0,0,0,10,0,0],
        [0,0,0,0,0,9.8,0],
        [0,0,0,0,0,0,10],
        [0,0,0,0,0,0,10],
        [0,0,0,0,0,0,0]
    ]
)

link_t = np.array(
    [
        [0,4,4,4,0,0,0],
        [0,0,0,0,0,0,4],
        [0,0,0,0,4,0,0],
        [0,0,0,0,0,6,0],
        [0,0,0,0,0,0,4],
        [0,0,0,0,0,0,4],
        [0,0,0,0,0,0,0]
    ]
)

O0 = np.zeros([7,7])
O3 = np.zeros([7,7])
traffic = np.array(
    [
        [1,0,6,4,4]
    ]
)

#print(selectroute(C0,link_type,0,6,4,4))

th = te(C0,O0,traffic,link_t)
print(th)


