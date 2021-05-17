import dns.resolver as resolver

def verify_domain(domain):
    '''Verify if host name exists'''
    try:
        hosts = resolver.resolve(domain)
        print('1')
        print(hosts)
    except resolver.NXDOMAIN:
        print('NXDOMAIN: %s' % domain)
        return
    except resolver.NoAnswer:
        print('NoAnswer: %s' % domain)
        return
    except resolver.NoNameservers:
        print('NoNameservers: %s' % domain)
        return


verify_domain('wppppp.pl')