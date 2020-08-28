#!/usr/bin/python3
import requests
import hashlib
import argparse
import os.path
import csv


def test(string):
    #string=string.encode('UTF-8')
    #print(string)
    r =requests.get('https://api.pwnedpasswords.com/range/'+string) #testing 5chars of hash
    #length = len(r..splitlines())
    #return "dupa"
    l = len(r.text.splitlines())
    return l

def enum():
    start = 0x00000  # hex literal, gives us a regular integer
    end = 0xfffff
    enumarr = []
    dict = {}
    f = open("hibp.csv", "a")


    for i in range(start, end + 1):
        testvalue="{0:0{1}x}".format(i,5)
        #dict[testvalue]=test(testvalue)
        f.write(str(testvalue) + "," + str(test(testvalue))+'\n')
        #print(str(testvalue) + "," + str(test(testvalue)))
    #print(dict)
    #fnames = ['hash', 'count']
    f.close()
    #w = csv.writer(open("output.csv", "w"))
    #for key, val in dict.items():
    #    w.writerow([key, val])
            
        
    

enum()