"""Administrative-only diagnostic routes; attach behind the existing Ingress guard."""
import asyncio
from aiohttp import web

from shared.http import DIAGNOSTICS


def filters(request):
    permitted={'before','limit','level','component','since','until'}
    if set(request.query)-permitted: raise ValueError('Invalid diagnostic filters')
    result={}
    for key in permitted:
        if request.query.get(key):
            value=request.query[key]
            result[key]=int(value) if key=='limit' else float(value) if key in ('since','until') else value
    return result


def add_diagnostics_routes(app, diagnostics):
    if diagnostics is None: return
    app[DIAGNOSTICS]=diagnostics
    async def page(request):
        result=await asyncio.to_thread(diagnostics.page,**filters(request))
        result['summary']=diagnostics.snapshot()
        return web.json_response(result)
    async def export(request):
        selected=filters(request)
        if set(selected)&{'before','limit'}: raise ValueError()
        diagnostics.page(limit=1,**selected)
        response=web.StreamResponse(headers={'Content-Type':'application/x-ndjson',
            'Content-Disposition':'attachment; filename="ha-tunnel-diagnostics.jsonl"','Cache-Control':'no-store'})
        await response.prepare(request)
        # Iteration is bounded by the five files, off the request's event loop.
        rows=await asyncio.to_thread(lambda:list(diagnostics.export(**selected)))
        for row in rows: await response.write(row)
        await response.write_eof()
        return response
    app.add_routes([web.get('/api/diagnostics',page),web.get('/api/diagnostics/export',export)])
