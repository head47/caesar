import idaapi
import networkx as nx
import matplotlib.pyplot as plt

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
        funcs = ['main']
        connections = []
        i = 0
        while i < len(funcs):
            function = idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,funcs[i]))
            rangeSet = idaapi.rangeset_t()
            idaapi.get_func_ranges(rangeSet,function)
            rangeList = list(rangeSet)
            for range in rangeList:
                curAddr = range.start_ea
                while curAddr < range.end_ea:
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

        subax1 = plt.subplot(121)
        nx.draw(funcG, with_labels=True)
        subax2 = plt.subplot(122)
        nx.draw(dividedG, with_labels=True)
        plt.show()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()
