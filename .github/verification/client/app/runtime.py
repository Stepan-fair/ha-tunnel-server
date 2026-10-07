from shared.runtime import FrpRuntime


def client_config(credentials, ca_path):
    return {
        'user':credentials['client_id'], 'serverAddr':credentials['tunnel_host'],
        'serverPort':credentials['tunnel_port'],'loginFailExit':False,
        'auth':{'method':'oidc','additionalScopes':['HeartBeats','NewWorkConns'],
                'oidc':{'clientID':credentials['client_id'],'clientSecret':credentials['secret'],
                        'audience':'ha-tunnel','tokenEndpointURL':credentials['server_url']+'/v1/token'}},
        'transport':{'protocol':'tcp','poolCount':1,'heartbeatInterval':30,'heartbeatTimeout':90,'tls':{
            'enable':True,'serverName':credentials['tunnel_host'],'trustedCaFile':str(ca_path)}},
        'proxies':[{'name':'ha','type':'http','localIP':'127.0.0.1','localPort':8123,
                    'customDomains':[credentials['domain']]}],
        'log':{'to':'console','level':'warn','disablePrintColor':True}}
