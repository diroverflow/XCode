#!/usr/bin/python -tt

import random

items=range(1,180)
f = open('xrand.h','w+')
for i in range(1,12):
    random.shuffle(items)
    cstr='#define XXX%d XCODE%d \\\nXCODE%d \\\nXCODE%d \\\nXCODE%d \\\nXCODE%d \\\nXCODE%d \\\nXCODE%d \\\nXCODE%d\n\n'%(i,items[0],items[1],items[2],items[3],items[4],items[5],items[6],items[7])
    print >>f,cstr
f.close()
