from shared.runtime import FrpRuntime


def server_config(pki, port=7000, http_port=18080, plugin_port=19000, bind='0.0.0.0'):
    return {
        'bindAddr':bind,'bindPort':port,'proxyBindAddr':'127.0.0.1',
        'vhostHTTPPort':http_port,'maxPortsPerClient':1,'userConnTimeout':10,
        'transport':{'maxPoolCount':5,'tls':{'force':True,'certFile':str(pki.cert),'keyFile':str(pki.key)}},
        'auth':{'method':'oidc','additionalScopes':['HeartBeats','NewWorkConns'],
                'oidc':{'issuer':f'http://127.0.0.1:{plugin_port}','audience':'ha-tunnel'}},
        'httpPlugins':[{'name':'ha-policy','addr':f'127.0.0.1:{plugin_port}','path':'/handler',
                        'ops':['Login','NewProxy','Ping','NewWorkConn','CloseProxy']}],
        'log':{'to':'console','level':'warn','disablePrintColor':True}}


class ServerRuntime(FrpRuntime):
    def __init__(self, binary, config_path, store, access=None, *, diagnostics=None):
        super().__init__(binary,config_path,diagnostics=diagnostics)
        self.store = store
        self.access = access

    async def revoke_and_disconnect(self, client_id):
        if self.access is not None:
            snap = self.store.access_snapshot(client_id, self.store.now())
            await self.access.command(client_id, 'revoke', __import__('secrets').token_hex(16), snap['revision'])
            return
        self.store.revoke(client_id)
        # Restart closes established HTTP/WebSockets, including pooled work connections.
        await self.restart()
