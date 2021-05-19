import argparse
import json
import os.path
from dns.rdatatype import NULL
import validators
import dns.resolver as resolver
import socket

def domain_verify(domain):
    #print('Verifying domain ' + domain)
    return validators.domain(domain)


def domain_resolve(domain):
    #print("Resolving domain " + domain)
    result={'CNAME':[],'A':[]}
    try:
        for rdata in resolver.resolve(domain, 'A') :
            rdata_lines=rdata.address.splitlines(True)
            for rdata_line in rdata_lines:
                result['A'].append(rdata_line)
        #    print(rdata_lines)
        #print(domain + ' - domain resolved to ' + str(rdata.address.splitlines(True)))
        try:
        #    print('2')
            for rdata in resolver.resolve(domain, 'CNAME') :
                result["CNAME"]=(rdata.target.to_text())
        except:
            #print("Oops!")
            result['CNAME']=False

        
        return result
    except resolver.NXDOMAIN:
        #result={'NX':True}
        #print(domain + ' - domain resolution failed.')
        return False
    except resolver.NoAnswer:
        #result={'NX':True}
        #print(domain + ' - domain resolution failed.')
        return False
    except resolver.NoNameservers:
        #result={'NX':True}
        #print(domain + ' - domain resolution failed.')
        return False


def port_check(address,port):
    #print("Checking port " + str(port) + " on host " + address)
    result={'TCP_'+str(port):False}
    s = socket.socket()
    s.settimeout(1)
    status=s.connect_ex((address, port))
    if status==0:
        result={'TCP_'+str(port):True}
        return result
    else:
        result={'TCP_'+str(port):False}
        return result
    s.close()

def get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb):
    #print((domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb))
    #result initialization
    result={'domain':domain}
    #domain validation
    if domain_verify(domain):
        #print(domain + ' - domain name verification: OK')
        #resolve domaincl

        #print('11111' + str(domain_resolve(domain)))

        if not domain_resolve(domain):
            result['error']="Domain resolution failed"
        else:   
            result={**result,**domain_resolve(domain)}
            if flag_netaccess:
                portcheck={'port_check':[]}
            #HTTP port check
                #print(port_check(domain,http_port))
                portcheck['port_check'].append({'protocol':'HTTP',**port_check(domain,http_port)})
            #HTTP port check
                #print(port_check(domain,https_port))
                portcheck['port_check'].append({'protocol':'HTTPS',**port_check(domain,https_port)})
                #print(portcheck)
                result={**result,**portcheck}
            
            #Cert check
            if flag_cert:
############################################  
# ####!!!!!!!!!!!!!!!!!!!!!!add content here 
# ####!!!!!!!!!!!!!!!!!!!!!!add content here 
# ####!!!!!!!!!!!!!!!!!!!!!!add content here 
# ####!!!!!!!!!!!!!!!!!!!!!!add content here 
# ####!!!!!!!!!!!!!!!!!!!!!!add content here 
# ####!!!!!!!!!!!!!!!!!!!!!!add content here 
# ##########################################             
                pass




    else:
        #print(domain + '- domain name verification: Failed')
        result['error']="Domain verification failed"

    
    return result

def test_file(filePath):
    fileExist=os.path.isfile(filePath)
    return fileExist

#read file need to be solved

def read_file(file):
    result=[]
    content=open(file, 'r')
    lines = content.readlines()
    if len(lines)==0:
        print(file + "is empty")
        result=False
        return result
    else:
        #print(lines)
        for item in lines:
            #print(item.strip())
            
            if item.rstrip():
                result.append(item.strip())
        #print(result)
    return result






def parse_file(file):
    print("Testing path: " + file)   
    error={}
    result=[]
    http_default=80
    https_default=443
    #print(test_file(file))
    if test_file(file):
        print('Parsing file: ' + file)
        items=read_file(file)
        for item in items:
            field=item.split(',')
            if (len(field)==1):
                field.append(http_default)
            elif field[1]=='':
                field[1]=http_default
            else:
                field[1]=int(field[1])

            if (len(field)==2):
                field.append(https_default)
            elif field[1]=='':
                field[1]=https_default
            else:
                field[2]=int(field[2])
            #print((field))
            result.append(field)
            #print(result)


        error={'error_code':0}
    else:
        print("Path provided:" + file + " is wrong or not accesible")
        result=False
    return result

def main():
    # Construct the argument parser
    ap = argparse.ArgumentParser(description='Domain Checker \r\n')

    # Add the arguments to the parser
    # Domain input args
    ap.add_argument('-f', '--file', required=False, help="File with domain list, each domain in new line. File format: domain(required),http_port(optional),https_port(optional). No header.")
    ap.add_argument('-d', '--domain', required=False, help="Domain for verification.")
    ap.add_argument('--http', required=False, help="HTTP port, used only if domain id provided (-d). Default: 80.", default=80)
    ap.add_argument('--https', required=False, help="HTTPS port, used only if domain id provided (-d). Default: 443.", default=443)
    # Output format args
    ap.add_argument('-o', '--output', required=False, help="Output type. Default: JSON", default='JSON')
    ap.add_argument('-p', '--path', required=False, help="Output path")

    # Checks (flags)
    ap.add_argument('--dns', required=False, help="Include dns resolve", action='store_true')
    ap.add_argument('--cert', required=False, help="Include cert info.", action='store_true')
    ap.add_argument('--net', required=False, help="Include network accesability", action='store_true')
    ap.add_argument('--ec', required=False, help="Include www error code response", action='store_true')
    ap.add_argument('--thumb', required=False, help="Include page thumbinal", action='store_true')
    # Parse args
    args = vars(ap.parse_args())
    file=args['file']
    domain=args['domain']
    http_port=args['http']
    https_port=args['https']
    output_type=args['output']
    output_path=args['path']
    flag_dns=args['dns']
    flag_cert=args['cert']
    flag_netaccess=args['net']
    flag_httpec=args['ec']
    flag_thumb=args['thumb']

    # Variables
    result = json.loads('{"domaininfo":[]}')

    # Arguments
    if domain==None and file==None:
        print("No domain provided \r\nPlease check help (-h) for more info.")
        #return False
    else:
        
            
        
        if file!=None:
            #print('Parse file output: ' + str(parse_file(file)))
            for item in parse_file(file):
                domain=item[0]
                http_port=item[1]
                https_port=item[2]
                #print(get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb))
                result['domaininfo'].append(get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb))
        
        elif domain!=None:
            result['domaininfo'].append(get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb))
            #result['domaininfo'].append(getdomaininfo(domain))


    print(result)
    return result

if __name__ == "__main__":
    main()

#TO DO
#Port Validation
#Thumbnail
#www response code
#disct to JSON
#JSON2HTML