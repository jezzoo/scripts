#!/usr/bin/python3
import requests
import pandas as pd 
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from scipy import randn

#import hashlib
#import argparse
#import os.path
#import csv


def test(string):
    #string=string.encode('UTF-8')
    #print(string)
    r =requests.get('https://api.pwnedpasswords.com/range/'+string) #testing 5chars of hash
    #length = len(r.splitlines())
    #return "dupa"
    
    return r.text

def linecount(blob):
    l = len(blob.splitlines())
    return l

def Sort(sub_li): 
  
    # reverse = None (Sorts in Ascending order) 
    # key is set to sort using second element of  
    # sublist lambda has been used 
    sub_li.sort(key = lambda x: x[1],reverse=True) 
    return sub_li 




def enum():
    start = 0x00000  # hex literal, gives us a regular integer
    end = 0x00001  # hex literal, gives us a regular integer
    
    for i in range(start, end + 1):
        testvalue="{0:0{1}x}".format(i,5)
        t=test(testvalue)
        print("-----------------------"+str(testvalue)+"-----------------------")
        #print(t)
        lines=t.splitlines()
        array=[]
        
        for line in lines:
            line=str(testvalue)+line
            line=line.split(":")
            #print(line[0])
            line[1]=int(line[1])
            array.append(line)
        #print(array)
        df=pd.DataFrame(array,columns=['hash','count'])
        df=df.sort_values(by=['count'], ascending=False)
        print(df)
        df.plot.bar(y='count')
        plt.show()
        #sortedarray=Sort(array)
        #print("sorted")
        #print(sortedarray[[2]]) 
        #print("-----------------------"+str(testvalue)+"-----------------------")
    
        df = pd.DataFrame(randn(1000, 4), index=ts.index, columns=list('ABCD'))
        df = df.cumsum()
        plt.figure(); df.plot(); plt.legend(loc='best')
        
    #enumarr = []
    #dict = {}
    #f = open("hibp.csv", "a")


    #for i in range(start, end + 1):
    #    testvalue="{0:0{1}x}".format(i,5)
    #    #dict[testvalue]=test(testvalue)
    #    if
    #    f.write(str(testvalue) + "," + str(test(testvalue))+'\n')
        #print(str(testvalue) + "," + str(test(testvalue)))
    #print(dict)
    #fnames = ['hash', 'count']
    #f.close()
    #w = csv.writer(open("output.csv", "w"))
    #for key, val in dict.items():
    #    w.writerow([key, val])
            
        
    

enum()