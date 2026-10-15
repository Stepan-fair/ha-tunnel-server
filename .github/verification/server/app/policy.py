"""FRP wire field whitelist; all unknown/unsafe proxy features fail closed."""
from server.app.routing import upstream_domain

DENY = {'reject':True,'reject_reason':'Access denied'}
ALLOW = {'reject':False,'unchange':True}
FIELDS = {'user','proxy_name','proxy_type','use_encryption','use_compression',
          'bandwidth_limit','bandwidth_limit_mode','group','group_key','remote_port',
          'custom_domains','subdomain','locations','http_user','http_pwd',
          'host_header_rewrite','headers','sk','multiplexer','metas',
          'route_by_http_user','response_headers'}
EMPTY_FIELDS = {'group','group_key','subdomain','locations','http_user','http_pwd',
                'host_header_rewrite','headers','sk','multiplexer','metas',
                'route_by_http_user','response_headers','remote_port'}


def authorize(op, content, store, authority, bandwidth_limit_mb=10):
    if type(bandwidth_limit_mb) is not int or not 1<=bandwidth_limit_mb<=1000:
        raise ValueError('Bandwidth limit must be 1 to 1000 MB/s')
    if not isinstance(content, dict):
        return dict(DENY)
    try:
        user = content.get('user') if op == 'Login' else content.get('user', {}).get('user')
        client = store.active(user)
        if client is None:
            return dict(DENY)
        generation=store.access_snapshot(client.client_id,store.now())['generation']
        if op in ('Login','Ping','NewWorkConn'):
            claims=authority.claims(content.get('privilege_key'))
            if claims['sub'] != client.client_id or claims.get('generation',0)!=generation:
                return dict(DENY)
        if op == 'Login':
            metas=content.get('metas') or {}
            if not isinstance(metas,dict): return dict(DENY)
            owner=store.admission.login(client.client_id,generation,content.get('run_id',''),
                metas.get('ha_tunnel_process'))
            if owner is None: return dict(DENY)
            return {'reject':False,'unchange':False,'content':{**content,
                'run_id':owner['run_id'],'client_id':client.client_id,'pool_count':1,
                'metas':{'ha_tunnel_generation':str(generation),'ha_tunnel_session':owner['epoch']}}}
        user=content.get('user',{})
        metas=user.get('metas',{})
        if not isinstance(metas,dict) or metas.get('ha_tunnel_generation')!=str(generation):
            return dict(DENY)
        identity=(client.client_id,generation,user.get('run_id'),metas.get('ha_tunnel_session'))
        if op in ('Ping','NewWorkConn'):
            if op=='NewWorkConn' and content.get('run_id')!=user.get('run_id'): return dict(DENY)
            if not store.admission.activity(*identity,op): return dict(DENY)
            store.seen(client.client_id,int(store.now()))
            return dict(ALLOW)
        if op == 'NewProxy':
            if (set(content) - FIELDS or content.get('proxy_type') != 'http' or
                    content.get('proxy_name') != client.client_id+'.ha' or
                    content.get('custom_domains') != [client.domain] or
                    any(content.get(key) for key in EMPTY_FIELDS)):
                return dict(DENY)
            # The server sets the bandwidth ceiling; the client cannot remove it.
            if not store.admission.activity(*identity,op): return dict(DENY)
            store.seen(client.client_id,int(store.now()))
            return {'reject':False,'unchange':False,'content':{
                **content,'bandwidth_limit':f'{bandwidth_limit_mb}MB','bandwidth_limit_mode':'server',
                'custom_domains':[upstream_domain(client.client_id,client.domain,generation)],
                'host_header_rewrite':client.domain}}
        if op == 'CloseProxy':
            if content.get('proxy_name') != client.client_id+'.ha': return dict(DENY)
            return dict(ALLOW if store.admission.close_proxy(*identity) else DENY)
    except (ValueError, TypeError, AttributeError):
        return dict(DENY)
    return dict(DENY)
