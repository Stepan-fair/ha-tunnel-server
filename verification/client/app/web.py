import asyncio
from pathlib import Path
import secrets
from aiohttp import web
from shared.http import safe_errors,ingress_middleware,csrf_for
from shared.presentation import format_metrics
from shared.help import documentation


def make_app(controller,options,admin_check=None):
    key=secrets.token_bytes(32)
    tasks=set()
    app=web.Application(client_max_size=8192,middlewares=[safe_errors,ingress_middleware(options,key,admin_check)])
    async def state(request):
        result=controller.status()
        result['presentation']=format_metrics(result.get('telemetry'),result.get('access'),
            options.get('timezone',(result.get('access') or {}).get('timezone','UTC')))
        return web.json_response({**result,'csrf':csrf_for(key,request.headers['X-Remote-User-Id'])})
    async def connect(request):
        data=await request.json()
        replacing=request.path.endswith('/replace-connection')
        if not isinstance(data,dict) or set(data)-({'invitation','confirmed'} if replacing else {'invitation'}):
            raise ValueError()
        if replacing and data.get('confirmed') is not True: raise ValueError()
        code=data.get('invitation') or None
        if code is not None and (not isinstance(code,str) or len(code)>2048):
            raise ValueError()
        if tasks:
            raise web.HTTPConflict()
        if (request.path.endswith('/rebind') or replacing) and code is None: raise ValueError()
        if replacing: operation=controller.replace_connection(code,confirmed=True)
        else:
            handler=controller.rebind if request.path.endswith('/rebind') else controller.connect
            operation=handler(code)
        task=asyncio.create_task(operation)
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return web.json_response({'status':'preparing'},status=202)
    async def index(request):
        return web.Response(body=(Path(__file__).parent/'templates/index.html').read_bytes(),content_type='text/html')
    async def help_page(request): return web.json_response({'text':documentation(__file__)})
    async def asset(request):
        name=request.match_info['name']
        if name not in ('app.js','style.css'):
            raise web.HTTPNotFound()
        return web.Response(body=(Path(__file__).parent/'templates'/name).read_bytes(),
                            content_type='text/javascript' if name.endswith('.js') else 'text/css')
    async def cleanup(app):
        for task in tuple(tasks): task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
    app.on_cleanup.append(cleanup)
    app.add_routes([web.get('/',index),web.get('/api/help',help_page),web.get('/api/state',state),web.post('/api/connect',connect),web.post('/api/rebind',connect),web.post('/api/replace-connection',connect),web.get('/{name}',asset)])
    return app
