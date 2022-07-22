#!/usr/bin/python3
# output to look like:
# {'gnulib': {'func1': [{'called_func1','called_func2'}, {'called_func3','called_func2'}],'func2': {'called_func1','called_func3'},...}}
import sys, os
#import pickle
import json
from pathlib import Path
from pycparser import c_ast, parse_file

FAKE_LIBC_LOCATION = '../pycparser/utils/fake_libc_include'
libname, libpath = sys.argv[1], Path(sys.argv[2])

try:
    #with open('funcs.pickle','rb') as f:
        #db = pickle.load(f)
    with open('funcs.json','r') as f:
        db = json.load(f)
except FileNotFoundError:
    db = {}

if libname not in db:
    db[libname] = {}

class FuncCallVisitor(c_ast.NodeVisitor):
    def __init__(self, par):
        super().__init__()
        self.called_funcs = []
        self.parent_func = par
    def visit(self, node):
        super().visit(node)
    def visit_FuncCall(self, node):
        if type(node.name) == c_ast.Cast:
            pass
        else:
            print(f'{self.parent_func} calls {node.name.name} at {node.coord}')
            if node.name.name not in self.called_funcs:
                self.called_funcs.append(node.name.name)
        if node.args:
            self.visit(node.args)

class FuncDefVisitor(c_ast.NodeVisitor):
    def visit_FuncDef(self, node):
        global db
        print(f'{node.decl.name} at {node.decl.coord}')
        v = FuncCallVisitor(node.decl.name)
        v.visit(node.body)
        called_funcs = v.called_funcs
        if node.decl.name not in db[libname]:
            db[libname][node.decl.name] = []
        if called_funcs not in db[libname][node.decl.name]:
            db[libname][node.decl.name].append(called_funcs)

def parse_funcs(filename, visitor):
    ast = parse_file(filename, use_cpp=True,
        cpp_args=[
            f'-I{FAKE_LIBC_LOCATION}',
            #f'-I{libpath}'
            f'-I{libpath.parent}'
        ])
    visitor.visit(ast)

#def multiparse(dirname):
#    vis = FuncDefVisitor()
#    files = {}
#    for file in os.listdir(dirname):
#        if file.endswith('.c') or file.endswith('.h'):
#            print(f'parsing {file}')
#            parse_funcs(os.path.join(dirname,file),vis)

print(db)
#multiparse(libpath)
vis = FuncDefVisitor()
parse_funcs(libpath, vis)
print(db)
#with open('funcs.pickle','wb') as f:
#    pickle.dump(db,f)
with open('funcs.json','w') as f:
    json.dump(db,f)
