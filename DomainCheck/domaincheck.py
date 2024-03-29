import argparse
import json
import os.path
from dns.rdatatype import NULL
import validators
import dns.resolver as resolver
import socket
import ssl
from json2html import *
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import io
from json2table import convert

#disable request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def domain_verify(domain):
    return validators.domain(domain)


def domain_resolve(domain):
    result={'CNAME':[],'A':[]}
    try:
        for rdata in resolver.resolve(domain, 'A') :
            rdata_lines=rdata.address.splitlines(True)
            for rdata_line in rdata_lines:
                result['A'].append(rdata_line)
        try:
            for rdata in resolver.resolve(domain, 'CNAME') :
                result["CNAME"]=(rdata.target.to_text())
        except:
            result['CNAME']="False"

        return result
    except resolver.NXDOMAIN:
        return False
    except resolver.NoAnswer:
        return False
    except resolver.NoNameservers:
        return False
    except resolver.Timeout:
        return False


def port_check(address,port):
    result={'TCP_'+str(port):False}
    s = socket.socket()
    s.settimeout(1)
    status=s.connect_ex((address, port))
    if status==0:
        result={'Port':str(port),'Status':True}
        return result
    else:
        result={'Port':str(port),'Status':False}
        return result
    s.close()


def tupletodict(tup):
    result=dict((x, y) for x, y in tup)
    return result

def getcert(domain,https_port):
    result={'subject':[],'issuer':[],'subjectAltName':[],'notBefore':"",'notAfter':""}
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, https_port))
            cert = s.getpeercert()
        #subject
        for i in range(len(cert['subject'])):
            subject=tupletodict(cert['subject'][i])
            result['subject'].append(subject)
        #issuer
        for i in range(len(cert['issuer'])):
            issuer=tupletodict(cert['issuer'][i])
            result['issuer'].append(issuer)

        #SAN
        subjectAltName={'DNS':[]}
        for i in range(len(cert['subjectAltName'])):
            san=cert['subjectAltName'][i][1]
            result['subjectAltName'].append(san)
        #cert dates
        result['notBefore']=cert['notBefore']
        result['notAfter']=cert['notAfter']
        #serial

        result['serialNumber']=cert['serialNumber']
    except Exception as e: 
        result='Exception: '+ str(e)
    return result

def get_http_ec(domain,protocol,port):
    result={}
    request_string=protocol+"://"+domain+":"+str(port)
    try:
        r = requests.get(request_string, verify=False)
        error_codes=[]
        for item in r.history:
            error_codes.append(str(item.status_code))
        error_codes.append(str(r.status_code))
        result={'http_error_code':{'request_string':request_string,'response_url':r.url,'http_response_codes':error_codes}}
    except Exception as e:
        result='Exception: ' + str(e)
    return result



def get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb,flag_all):
    #result initialization
    result={'domain':domain}
    #domain validation
    if domain_verify(domain):
        if not domain_resolve(domain):
            result['error']="Domain resolution failed"
        else:   
            result={**result,**domain_resolve(domain)}
            if (flag_netaccess or flag_all):
                portcheck={'port_check':[]}
            #HTTP port check
                portcheck['port_check'].append({'protocol':'HTTP',**port_check(domain,http_port)})
                http_status=portcheck['port_check'][0]['Status']
            #HTTPS port check
                portcheck['port_check'].append({'protocol':'HTTPS',**port_check(domain,https_port)})
                https_status=portcheck['port_check'][1]['Status']
                for i in range(len(portcheck['port_check'])):
                    portcheck['port_check'][i]['Status']=str(portcheck['port_check'][i]['Status'])
                portcheck
                result={**result,**portcheck}
            
            #Cert check
            if (flag_cert or flag_all):
                cert={'cert':NULL}
                if https_status:
                    cert={'cert':getcert(domain,https_port)}
                    result={**result,**cert}
                else:
                    pass
            
            #HTTP Error Code Check
            if (flag_httpec or flag_all):
                ec={'HTTP_error_code':[]}
                if https_status:
                   ec['HTTP_error_code'].append(get_http_ec(domain,'https',https_port))
                else:
                    pass
                
                if http_status:
                   ec['HTTP_error_code'].append(get_http_ec(domain,'http',http_port))
                   
                else:
                    pass
                result={**result,**ec}
                
            

    else:
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
        for item in lines:
             if item.rstrip():
                result.append(item.strip())
    return result

def parse_file(file):
    result=[]
    http_default=80
    https_default=443
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
            result.append(field)
    else:
        print("Path provided:" + file + " is wrong or not accesible")
        result=False
    return result

def save_output(output_path,json_string):
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(json_string, file, ensure_ascii=False, indent=4)

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
    #ap.add_argument('-o', '--output', required=False, help="Output type. Default: JSON", default='JSON')
    ap.add_argument('-p', '--path', required=False, help="Output path")

    # Checks (flags)
    ap.add_argument('--dns', required=False, help="Include dns resolve", action='store_true')
    ap.add_argument('--cert', required=False, help="Include cert info.", action='store_true')
    ap.add_argument('--net', required=False, help="Include network accesability", action='store_true')
    ap.add_argument('--ec', required=False, help="Include www error code response", action='store_true')
    ap.add_argument('--thumb', required=False, help="Include page thumbinal", action='store_true')
    ap.add_argument('--all', required=False, help="Include all tests", action='store_true')
    # Parse args
    args = vars(ap.parse_args())
    file=args['file']
    domain=args['domain']
    http_port=args['http']
    https_port=args['https']
    #output_type=args['output']
    output_path=args['path']
    flag_dns=args['dns']
    flag_cert=args['cert']
    flag_netaccess=args['net']
    flag_httpec=args['ec']
    flag_thumb=args['thumb']
    flag_all=args['all']

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
                result['domaininfo'].append(get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb,flag_all))
        
        elif domain!=None:
            result['domaininfo'].append(get_domain_info(domain,http_port,https_port,flag_cert,flag_dns,flag_httpec,flag_netaccess,flag_thumb,flag_all))
    json_string=json.dumps(result['domaininfo'])
    print(json_string)
    if output_path!='':
        save_output(output_path,result['domaininfo'])
    return result

if __name__ == "__main__":
    main()

#TO DO
#Thumbnail


