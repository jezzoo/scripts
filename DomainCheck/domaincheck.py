import socket
#import dnspython as dns
import dns.resolver as resolver
import ssl



#variables
domains=["adsales.discovery.com","cf-media.press.discovery.com","cregw1.discovery.com","dojo.dev.discovery.com"]
ports=[80,443]
#Functions

#domain check
def domaincheck(address):
    print("Checking domain "+address)
    result={'NX':False,'CNAME':[],'A':[]}
    try:
        for rdata in resolver.resolve(address, 'A') :
            rdata_lines=rdata.address.splitlines()
            result["A"].append(rdata_lines)
        #print('1')
        try:
        #    print('2')
            for rdata in resolver.resolve(address, 'CNAME') :
                result["CNAME"].append(rdata.target.to_text())
        except:
            #print("Oops!")
            result['CNAME']=False


        return result
    except resolver.NXDOMAIN:
        result={'NX':True}
        return result
    except resolver.NoAnswer:
        result={'NX':True}
        return result
    except resolver.NoNameservers:
        result={'NX':True}
        return result



#tcp connection
def portcheck(address,port):
    print("Checking port " + str(port) + " on host " + address)
    result={'TCP_'+str(port):False}
    s = socket.socket()
    s.settimeout(1)
    status=s.connect_ex((address, port))
    if status==0:
        result={'TCP_'+str(port):True}
        return result
    else:
        return result
    s.close()

def certcheck(address):
    print("Checking certificate for " + address)
    context = ssl.create_default_context()
    with socket.create_connection((address, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=address) as ssock:
            print(ssock.version())
            print(dir(ssock))
            print(ssock)


print('Port Checks')
print(portcheck('1.1.5.3',443))
print(portcheck('wp.pl',443))
print('domain check')
print(domaincheck('account.tvn.pl'))
print(domaincheck('konto.tvn.pl'))
print(domaincheck('asdadsadasdsadsa.sadsad'))
print(certcheck('account.tvn.pl'))
print('END')
