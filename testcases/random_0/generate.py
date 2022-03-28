#!/usr/bin/python3
import random
import string
import os

FUNCNUM = 100
THRESHOLD = 5

string_ = """#include <iostream>
using namespace std;

"""
randomDict = string.ascii_uppercase + string.ascii_lowercase + string.digits

for i in range(FUNCNUM):
    toPrint = ''.join(random.choices(randomDict, k=5))
    string_ += f"void func{i}() {{"
    string_ += '\n'
    for j in range(0,i):
        if random.randint(1,FUNCNUM) <= 5:
            string_ += f"  func{j}();"
            string_ += '\n'
    string_ += f"  cout << \"{toPrint}\";"
    string_ += "\n}\n\n"

string_ += "int main() {\n"
for i in range(FUNCNUM):
    string_ += f"  func{i}();"
    string_ += '\n'
string_ += '}'

with open('main.cpp','w') as outfile:
    outfile.write(string_)
os.system('build.bat')
