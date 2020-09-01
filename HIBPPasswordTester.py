#!/usr/bin/python3
import requests
import hashlib
import argparse
import os.path

# ------------------------------FUNCTIONS------------------------------------#
# Function to test password in HIBP - using k-Anonymity. Only 5 first characters of your password sha1 hash is send to internet
def testPass(passwd):
    print("\n//-----------------------------------------------------------------\n")
    print("Testing password: " + passwd)
    passwd=passwd.encode('UTF-8')
    passsha1=(hashlib.sha1(passwd).hexdigest()).upper()
    print("password hash: " + passsha1)
    hashtop5=passsha1[:5]
    hashnotop5=passsha1[5:]
    print("Sending: " + hashtop5 + " to test...")
    r =requests.get('https://api.pwnedpasswords.com/range/'+hashtop5)
    print("Searching hash in returned blob")
    line=findLine(hashnotop5,r.text)
    if not line==None:
        print('Hash found '+ line.split(":")[1] + " times. Do not use tested password!")
    else:
        print("Hash not found.")

def testFilePass(filePath):
    passBlob=readFile(filePath)
    if not readFile(filePath):
        print("Empty file")
    else:
        for item in passBlob:
            testPass(item.strip())


# ------------------HELPER------FUNCTIONS------------------------------------#
# Find string in text and return line - used to find hash (without first 5 chars) in hash list recieved from HIBP     
def findLine(pattern,text):
    for item in text.split("\n"):
        if pattern in item:
            return item.strip()

# Test if file exist
def testFile(filePath):
    fileExist=os.path.isfile(filePath)
    return fileExist

#Read file 
def readFile(filePath):
    passfile = open(filePath, 'r') 
    lines = passfile.readlines()
    if len(lines)==0:
        return False
    else:
        return lines

# ------------------------------MAIN------------------------------------#
def main():
    # Construct the argument parser
    ap = argparse.ArgumentParser(description='Test passwords in haveibeenpwned leaked passwords database. Test is secure, only 5 chars from passwords hash are sent to HIBP server. To learn more look for k-Anonimity.')

    # Add the arguments to the parser
    ap.add_argument('-p', '--password', required=False, help="Password to test")
    ap.add_argument('-f', '--file', required=False, help="File with passwords, each password in new line")
    args = vars(ap.parse_args())
    # Arguments
    if args["password"]==None and args["file"]==None:
        print("No password to test \r\nPlease check help (-h) for more info.")
    else:
        if args["password"]!=None:
            passwd=args["password"]
            testPass(passwd)
        if args["file"]!=None:
            print("Testing path: " + args["file"])    
            if testFile(args["file"]):
                print("Path OK")
                testFilePass(args["file"])
            else:
                print("Path provided is wrong or inaccesible")

if __name__ == "__main__":
    main()
