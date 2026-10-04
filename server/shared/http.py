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
        count, start=self.buckets.get(key,(0,now))
        if now-start>=period:
            count,start=0,now
        self.buckets[key]=(count+1,start)
        self.buckets.move_to_end(key)
        if len(self.buckets)>4096:
            self.buckets.popitem(last=False)
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
    return response


def ingress_middleware(options, csrf_key):
    @web.middleware
    async def guard(request, handler):
        user=request.headers.get('X-Remote-User-Id','')
        if request.remote not in options.get('ingress_ips',['172.30.32.2']):
            raise web.HTTPForbidden()
        if not user or user not in options.get('admin_user_ids',[]):
            raise web.HTTPForbidden()
        if request.method not in ('GET','HEAD'):
            value=request.headers.get('X-CSRF-Token','')
            if not hmac.compare_digest(value,csrf_for(csrf_key,user)):
                raise web.HTTPForbidden()
        return await handler(request)
    return guard
