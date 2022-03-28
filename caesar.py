import idaapi

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

        print(funcs)
        print(connections)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()
