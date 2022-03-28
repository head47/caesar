import idaapi
import networkx as nx
import matplotlib.pyplot as plt

SINGLETON_ADOPTION = True
ADOPTION_THRESHOLD = 2

def highly_connected(G,E):
    return len(E) > len(G.nodes) / 2

def HCS(G_):
    G = G_.copy()
    if len(G.nodes) == 1:
        return G
    E = nx.algorithms.connectivity.cuts.minimum_edge_cut(G)
    if not highly_connected(G,E):
        G.remove_edges_from(E)
        print('removing',E)
        subgraphs = [G.subgraph(c).copy() for c in nx.connected_components(G)]
        subgraphs[0] = HCS(subgraphs[0])
        subgraphs[1] = HCS(subgraphs[1])
        G = nx.compose(subgraphs[0],subgraphs[1])
    return G

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "Caesar"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
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
            for singleton in clusters:
                if len(singleton) == 1:
                    nearest = None
                    minConn = ADOPTION_THRESHOLD-1
                    for i in range(0,len(clusters)):
                        connNum = 0
                        for node2 in clusters[i]:
                            if funcG.has_edge(singleton[0],node2):
                                connNum += 1
                        if (connNum > minConn):
                            nearest = i
                            minConn = connNum
                    if nearest is not None:
                        print('adopting',singleton[0],'to',clusters[nearest])
                        dividedG.add_edge(singleton[0],clusters[nearest][0])
                    else:
                        print('could not adopt',singleton[0])
            clusters = [list(c) for c in nx.connected_components(dividedG)]
        print('clusters:',clusters)
        for i in range(0,len(clusters)):
            if len(clusters[i]) == 1:
                continue
            for funcName in clusters[i]:
                funcAddr = idaapi.get_name_ea(idaapi.BADADDR,funcName)
                idaapi.set_name(funcAddr,f'L{i}_{funcName}')

        subax1 = plt.subplot(121)
        nx.draw(funcG, with_labels=True)
        subax2 = plt.subplot(122)
        nx.draw(dividedG, with_labels=True)
        plt.show()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()
