import idaapi
import networkx as nx
import matplotlib.pyplot as plt
import random

SINGLETON_ADOPTION = True
ADOPTION_THRESHOLD = 0.3
SEED = 0

random.seed(SEED)
adopted = []

def highly_connected(G,E):
    return len(E) > len(G.nodes) / 2

def HCS(G_):
    G = G_.copy()
    if len(G.nodes) == 1:
        return G
    try:
        E = nx.algorithms.connectivity.cuts.minimum_edge_cut(G)
    except nx.exception.NetworkXError as err:
        if err.args[0] == "Input graph is not connected":
            E = ()
    if not highly_connected(G,E):
        G.remove_edges_from(E)
        print('removing',E)
        subgraphs = [G.subgraph(c).copy() for c in nx.connected_components(G)]
        for i in range(0,len(subgraphs)):
            subgraphs[i] = HCS(subgraphs[i])
        G = nx.compose_all(subgraphs)
    return G

def adopt(funcG,dividedG,clusters):
    contFlag = True
    while contFlag:
        contFlag = False
        for singleton in clusters:
            if len(singleton) == 1:
                nearest = []
                minConn = ADOPTION_THRESHOLD
                for i in range(0,len(clusters)):
                    connNum = 0
                    for node2 in clusters[i]:
                        if funcG.has_edge(singleton[0],node2):
                            connNum += 1
                    connNum /= len(clusters[i])
                    if (connNum > minConn):
                        nearest = [i]
                        minConn = connNum
                    elif (connNum == minConn):
                        nearest.append(i)
                if len(nearest) > 0:
                    chosenCluster = random.choice(nearest)
                    chosenNode = random.choice(clusters[chosenCluster])
                    print('adopting',singleton[0],'to',clusters[chosenCluster])
                    adopted.append(singleton[0])
                    dividedG.add_edge(singleton[0],chosenNode)
                    clusters = [list(c) for c in nx.connected_components(dividedG)]
                    contFlag = True
                    break
                else:
                    print('could not adopt',singleton[0])
    return clusters

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "Caesar"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        global adopted
        #funcs = {
        #    'main': idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'main'))
        #}
        if idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'main')) is not None:
            funcs = ['main']
        elif idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'_main')) is not None:
            funcs = ['_main']
        else:
            funcs = [idaapi.ask_ident(
                '','Could not detect main function, please specify it manually'
            )]
        connections = []
        i = 0
        while i < len(funcs):
            function = idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,funcs[i]))
            rangeSet = idaapi.rangeset_t()
            idaapi.get_func_ranges(rangeSet,function)
            rangeList = list(rangeSet)
            for rng in rangeList:
                curAddr = rng.start_ea
                while curAddr < rng.end_ea:
                    insn = idaapi.insn_t()
                    insnLen = idaapi.decode_insn(insn, curAddr)
                    if insn.get_canon_mnem() == 'call':
                        calledAddr = insn.ops[0].addr
                        calledName = idaapi.get_func_name(calledAddr)
                        if calledName is not None:
                            if calledName not in funcs:
                                funcs.append(calledName)
                            if [funcs[i],calledName] not in connections:
                                connections.append([funcs[i],calledName])
                    curAddr += insnLen
            i += 1

        funcG = nx.Graph()
        funcG.add_edges_from(connections)
        print(funcG.nodes)
        print(funcG.edges)
        dividedG = HCS(funcG)
        clusters = [list(c) for c in nx.connected_components(dividedG)]
        # singleton adoption
        if SINGLETON_ADOPTION:
            clusters = adopt(funcG,dividedG,clusters)
        print('clusters:',clusters)
        for i in range(0,len(clusters)):
            if len(clusters[i]) == 1:
                continue
            for funcName in clusters[i]:
                funcAddr = idaapi.get_name_ea(idaapi.BADADDR,funcName)
                if funcName not in adopted:
                    idaapi.set_name(funcAddr,f'C{i}_{funcName}')
                else:
                    idaapi.set_name(funcAddr,f'C{i}AD_{funcName}')
        adopted = []

        subax1 = plt.subplot(121)
        nx.draw(funcG, with_labels=True)
        subax2 = plt.subplot(122)
        nx.draw(dividedG, with_labels=True)
        plt.show()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()
