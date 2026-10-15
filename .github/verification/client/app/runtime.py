import json
import secrets
from shared.files import atomic_write
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


class ClientRuntime(FrpRuntime):
    async def _launch(self):
        # Each OS process gets a new hint. Native reconnects keep this config,
        # while restart (including crash recovery) gets a fresh process nonce.
        config={**self.config,'metadatas':{**self.config.get('metadatas',{}),
            'ha_tunnel_process':secrets.token_hex(32)}}
        atomic_write(self.path,json.dumps(config,separators=(',',':')).encode())
        await super()._launch()
