#!/usr/bin/python3
import argparse
from Registry import Registry

parser = argparse.ArgumentParser()
parser.add_argument('-f', dest='inputfile')
parser.add_argument('-o', dest='outfile')
args = parser.parse_args()

f = open(args.outfile, 'a')
reg = Registry.Registry(args.inputfile)


def rec(key, depth=0):
    for subkey in key.subkeys():
        rec(subkey, depth + 0)
        for value in [v for v in key.values()
                      if v.value_type() == Registry.RegBin]:
            shorten = value.value()
            shorten = shorten.decode('utf-16').rstrip('\x00')


rec(reg.root())
f.close()
