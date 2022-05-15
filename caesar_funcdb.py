import idaapi
import networkx as nx
import json

MAX_PASSES = 1000

class Function:
    def __init__(self,idaname):
        self.idaname = idaname
        self.guesses = []
        self.probability = 0
        self.address = idaapi.get_name_ea(idaapi.BADADDR,idaname)
        self.called_funcs = self.calc_called_funcs()
        self.calling_funcs = set() # populated externally

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

    def expandCalled(self, funcDict):
        '''Takes a set of called idanames and transforms it into a list of lists
        of guessed names'''
        called_funcs = list(self.called_funcs)
        candList = [] # contains candidates for each of the called functions
        for func in called_funcs:
            guesses = funcDict[func].guesses
            candidates = []
            if len(guesses) == 0:
                candidates.append(None)
            for guess in guesses:
                candidates.append(guess[1])
            candList.append(candidates)
        perms = permutations(candList)
        res = []
        if len(perms) == 0:
            return res
        initlen = len(perms[0])
        for i in range(len(perms)):
            valid = True
            # check for duplicates: 1 def for 1 func
            for j in range(len(perms[i])):
                for k in range(j+1,len(perms[i])):
                    if (perms[i][j] == perms[i][k]) and (perms[i][j] is not None):
                        valid = False
                        break
                if not valid:
                    break
            if valid:
                res.append(perms[i])
        return res

class Entry:
    def __init__(self,lib,name,cfl):
        self.lib = lib
        self.name = name
        self.called_funcs = cfl

def permutations(list_):
    '''Calculates possible permutations, given the list of candidates for each
    position'''
    if len(list_) <= 1:
        return list_
    perms = []
    if len(list_) == 2:
        for i in list_[0]:
            for j in list_[1]:
                perms.append([i,j])
    else:
        prevPerms = permutations(list_[:-1])
        for i in list_[-1]:
            for j in prevPerms:
                j = j.copy()
                j.append(i)
                perms.append(j)
    return perms

def sorensen(a, b):
    '''Calculates Sorensen-Dice coefficient for two given lists or sets'''
    common = len([func for func in a if func in b])
    coeff = 2*common/(len(a)+len(b))
    return coeff

def similarity(actual, entry, funcDict):
    '''Calculate similarity between a Function and an Entry'''
    calledB = entry.called_funcs
    calledAList = actual.expandCalled(funcDict)
    coeffs = []
    for i in calledAList:
        coeffs.append(sorensen(i,calledB))
    if len(coeffs) == 0:
        return 0
    return sum(coeffs) / len(coeffs)

class caesar_funcdb_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "Caesar (FuncDB)"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        entryList = []
        # populate entry list
        try:
            with open('funcs.json','r') as f:
                db = json.load(f)
        except FileNotFoundError:
            db = {}
        for lib in db:
            for func in db[lib]:
                for cfl in db[lib][func]:
                    entryList.append(Entry(lib,func,cfl))
        if idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'main')) is not None:
            mainFName = 'main'
        elif idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,'_main')) is not None:
            mainFName = '_main'
        else:
            mainFName = idaapi.ask_ident(
                '','Could not detect main function, please specify it manually'
            )
        queue = [mainFName]
        funcDict = {}
        # populate Function dict
        for funcName in queue:
            funcDict[funcName] = Function(funcName)
            calledFuncs = funcDict[funcName].called_funcs
            for calledFunc in calledFuncs:
                if calledFunc not in queue:
                    queue.append(calledFunc)
        # print all funcs
        for func_name in funcDict:
            print(f'{func_name} calls: {funcDict[func_name].called_funcs}')
        # create directed graph of functions
        funcG = nx.DiGraph()
        for funcName in funcDict:
            function = funcDict[funcName]
            for calledFunc in function.called_funcs:
                funcG.add_edge(funcName,calledFunc)
        # populate calling_funcs
        for funcName in funcDict:
            for callingFunc in funcG.predecessors(funcDict[funcName].idaname):
                funcDict[funcName].calling_funcs.add(callingFunc)
        # 1st pass: identify extern stubs
        for func_name in funcDict:
            if func_name.startswith('.'):
                realname = func_name[1:]
                funcDict[func_name].guesses = [('EXTERN/FLIRT',realname)]
                funcDict[func_name].probability = 1
                print(f'{func_name} identified as {realname} (EXTERN/FLIRT)')
        # next passes: update all possible functions
        for passCount in range(MAX_PASSES):
            updated = False
            for func_name in funcDict:
                if func_name.startswith('.'):
                    continue
                for entry in entryList:
                    probability = similarity(funcDict[func_name], entry, funcDict)
                    if probability == 0:
                        continue
                    if probability > funcDict[func_name].probability:
                        updated = True
                        funcDict[func_name].guesses = [(entry.lib,entry.name)]
                        funcDict[func_name].probability = probability
                        print(f'{func_name} identified as {entry.name} ({entry.lib}, {funcDict[func_name].probability*100:.2f}%)')
                    elif probability == funcDict[func_name].probability:
                        if (entry.lib,entry.name) not in funcDict[func_name].guesses:
                            updated = True
                            funcDict[func_name].guesses.append((entry.lib,entry.name))
                            print(f'{func_name} identified as {entry.name} ({entry.lib}, {funcDict[func_name].probability*100:.2f}%)')
            if not updated:
                break
        if updated:
            print("WARNING: MAX_PASSES reached, Caesar stopped")
        # add function comments
        for func_name in funcDict:
            idaname = funcDict[func_name].idaname
            guesses = funcDict[func_name].guesses
            probability = funcDict[func_name].probability*100
            if len(guesses) == 0:
                comment = "Detected function: n/a"
            elif len(guesses) == 1:
                comment = f"Detected function: {guesses[0][1]}"
                comment+= '\n'+f"Detected library: {guesses[0][0]}"
                comment+= '\n'+f"Probability: {probability:.2f}%"
            else:
                comment = "Possible functions:"
                for i in range(len(guesses)):
                    comment += '\n'+f'{i+1}. {guesses[0][1]} from {guesses[0][0]}'
                comment+= '\n'+f'Probability: {probability:.2f}%'
            funct = idaapi.get_func(idaapi.get_name_ea(idaapi.BADADDR,idaname))
            idaapi.set_func_cmt(funct,comment,False)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return caesar_funcdb_plugin_t()
