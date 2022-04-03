#!/usr/bin/python3
import random
import string
import os

FUNCNUM = 20
THRESHOLD = 5
LIBNUM = 9
SEED = 0

random.seed(SEED)
mainContent = '#include <iostream>\n'
for k in range(1,LIBNUM+1):
    mainContent += f'#include <lib{k}.h>'+'\n'
mainContent += """using namespace std;

"""
randomDict = string.ascii_uppercase + string.ascii_lowercase + string.digits

for i in range(FUNCNUM):
    toPrint = ''.join(random.choices(randomDict, k=5))
    mainContent += f"void func{i}() {{"
    mainContent += '\n'
    for j in range(0,i):
        if random.randint(1,FUNCNUM) <= THRESHOLD:
            mainContent += f"  func{j}();"
            mainContent += '\n'
    mainContent += f"  cout << \"{toPrint}\";"
    mainContent += "\n}\n\n"

mainContent += "int main() {\n"
for i in range(FUNCNUM):
    mainContent += f"  func{i}();"
    mainContent += '\n'
for k in range(1,LIBNUM+1):
    mainContent += f"  func{(k+1)*FUNCNUM-1}();"+'\n'
mainContent += '}'

with open('main.cpp','w') as outfile:
    outfile.write(mainContent)

for k in range(1,LIBNUM+1):
    libContent = """#include <iostream>
using namespace std;

"""
    headerContent = f"#ifndef LIB{k}_H"+'\n'+f"#define LIB{k}_H"+'\n\n'

    for i in range(FUNCNUM):
        toPrint = ''.join(random.choices(randomDict, k=5))
        libContent += f"void func{k*FUNCNUM+i}() {{"+'\n'
        headerContent += f"void func{k*FUNCNUM+i}();"+'\n'
        for j in range(0,i):
            if random.randint(1,FUNCNUM) <= THRESHOLD*3:
                libContent += f"  func{k*FUNCNUM+j}();"+'\n'
        libContent += f"  cout << \"{toPrint}\";"+'\n}\n\n'
    headerContent += '\n#endif'
    with open(f'lib{k}.cpp','w') as outfile:
        outfile.write(libContent)
    with open(f'lib{k}.h','w') as outfile:
        outfile.write(headerContent)

buildCommand = 'g++ -o test.exe -I. main.cpp'
for k in range(1,LIBNUM+1):
    buildCommand += f' lib{k}.cpp'
print(buildCommand)
os.system(buildCommand)
