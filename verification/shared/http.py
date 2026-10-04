"""Small bounded helpers shared by the three separate listener surfaces."""
from collections import OrderedDict
import hashlib
import hmac
import secrets
import time
from aiohttp import web


class Limits:
    def __init__(self):
        self.buckets = OrderedDict()

    def allow(self, key, maximum, period=60):
        now=time.monotonic()
        if key not in self.buckets:
            if len(self.buckets)>=4096:
                for expired in [k for k,(_,until) in self.buckets.items() if until<=now]:
                    del self.buckets[expired]
                if len(self.buckets)>=4096: return False
            count,until=0,now+period
        else:
            count,until=self.buckets[key]
            if now>=until: count,until=0,now+period
        self.buckets[key]=(min(count+1,maximum),until)
        return count<maximum


def csrf_for(key, user):
    return hmac.new(key,user.encode(),hashlib.sha256).hexdigest()


@web.middleware
async def safe_errors(request, handler):
    try:
        response=await handler(request)
    except web.HTTPException as exc:
        response=web.json_response({'error':exc.reason},status=exc.status)
    except (ValueError, TypeError, KeyError):
        response=web.json_response({'error':'Invalid request'},status=400)
    except Exception:
        # Do not log request bodies, JWTs, credentials or exception repr.
        response=web.json_response({'error':'Service unavailable'},status=503)
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
                             'Referrer-Policy':'no-referrer',
                             'Content-Security-Policy':"default-src 'self'; style-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'"})
    if request.get('trusted_https'):
        response.headers['Strict-Transport-Security']='max-age=31536000'
    return response


def ingress_middleware(options, csrf_key, admin_check=None):
    @web.middleware
    async def guard(request, handler):
        user=request.headers.get('X-Remote-User-Id','')
        if request.remote not in options.get('ingress_ips',['172.30.32.2']):
            raise web.HTTPForbidden()
        if not user or ('admin_user_ids' in options and user not in options['admin_user_ids']):
            raise web.HTTPForbidden()
        # Runtime supplies actual HA verification; explicit allowlists are also
        # useful for isolated tests. No callback and no allowlist fails closed.
        if admin_check is None and 'admin_user_ids' not in options:
            raise web.HTTPForbidden()
        if admin_check is not None:
            try: allowed=await admin_check(user)
            except Exception: allowed=False
            if allowed is not True: raise web.HTTPForbidden()
        if request.method not in ('GET','HEAD'):
            value=request.headers.get('X-CSRF-Token','')
            if not hmac.compare_digest(value,csrf_for(csrf_key,user)):
                raise web.HTTPForbidden()
        return await handler(request)
    return guard
