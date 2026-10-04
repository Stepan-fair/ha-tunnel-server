"""FRP wire field whitelist; all unknown/unsafe proxy features fail closed."""
import time
import secrets
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
            if op in ('Login', 'Ping'):
                store.seen(client.client_id, int(time.time()))
            if op=='Login':
                nonce = secrets.token_hex(16)
                store.login_sessions[client.client_id] = nonce
                return {'reject':False,'unchange':False,'content':{**content,'metas':{'ha_tunnel_generation':str(generation),'ha_tunnel_session':nonce}}}
            return dict(ALLOW)
        if op == 'NewProxy':
            value=content.get('user',{}).get('metas',{}).get('ha_tunnel_generation')
            if value!=str(generation) and not (generation==0 and value is None): return dict(DENY)
            session = content.get('user',{}).get('metas',{}).get('ha_tunnel_session')
            if session != store.login_sessions.get(client.client_id): return dict(DENY)
            if (set(content) - FIELDS or content.get('proxy_type') != 'http' or
                    content.get('proxy_name') != client.client_id+'.ha' or
                    content.get('custom_domains') != [client.domain] or
                    any(content.get(key) for key in EMPTY_FIELDS)):
                return dict(DENY)
            # The server sets the bandwidth ceiling; the client cannot remove it.
            store.live_proxies[client.client_id]=generation
            store.live_sessions[client.client_id]=(generation,session)
            return {'reject':False,'unchange':False,'content':{
                **content,'bandwidth_limit':f'{bandwidth_limit_mb}MB','bandwidth_limit_mode':'server',
                'custom_domains':[upstream_domain(client.client_id,client.domain,generation)],
                'host_header_rewrite':client.domain}}
        if op == 'CloseProxy':
            metas = content.get('user',{}).get('metas',{})
            identity = (int(metas.get('ha_tunnel_generation',0)),metas.get('ha_tunnel_session'))
            if store.live_sessions.get(client.client_id) == identity:
                store.live_proxies.pop(client.client_id,None)
                store.live_sessions.pop(client.client_id,None)
            return dict(ALLOW)
    except (ValueError, TypeError, AttributeError):
        return dict(DENY)
    return dict(DENY)
