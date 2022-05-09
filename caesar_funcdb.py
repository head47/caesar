import idaapi

class Function:
    def __init__(self,idaname):
        self.idaname = idaname
        self.realname = None
        self.address = idaapi.get_name_ea(idaapi.BADADDR,idaname)
        self.called_funcs = self.calc_called_funcs()

    def __repr__(self):
        return f"<Function '{self.idaname}' at {hex(self.address)}"

    def calc_called_funcs(self):
        called_funcs = set()
        function = idaapi.get_func(self.address)
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
                    if (calledName is not None) and (calledName not in called_funcs):
                        called_funcs.add(calledName)
                curAddr += insnLen
        return called_funcs

class caesar_funcdb_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "Caesar (FuncDB)"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        if idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'main')) is not None:
            queue = ['main']
        elif idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'_main')) is not None:
            queue = ['_main']
        else:
            queue = [idaapi.ask_ident(
                '','Could not detect main function, please specify it manually'
            )]
        funcDict = {}
        # populate Function dict
        for funcName in queue:
            funcDict[funcName] = Function(funcName)
            calledFuncs = funcDict[funcName].called_funcs
            for calledFunc in calledFuncs:
                if calledFunc not in queue:
                    queue.append(calledFunc)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return caesar_funcdb_plugin_t()
