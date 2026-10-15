"""Linux-only bounded real-FRP comparison in the current isolated test image.

Source may be a frozen public predecessor tree; FRP and dependencies always
come from the current patched image. No remote targets or production data.
"""
import argparse
import asyncio
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import time
from urllib.parse import urlsplit


def process_usage(pid):
    status=(Path('/proc')/str(pid)/'status').read_text()
    rss=int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))*1024
    stat=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()
    return rss,(int(stat[11])+int(stat[12]))/os.sysconf('SC_CLK_TCK')


async def measure(root,directory):
    from shared.runtime import FrpRuntime
    import client.app.runtime as client_runtime
    import server.app.web as web
    from server.app.relay import ClientRelay
    from server.app.access import AccessService
    # Frozen sources own application imports, but never shadow current harness
    # helpers with their older tests/tools packages (which lack these modules).
    established_sockets=runpy.run_path(str(root/'tests/frp_socket_evidence.py'))['established_sockets']
    rss_bytes=runpy.run_path(str(root/'tools/performance_acceptance.py'))['rss_bytes']
    fixture=runpy.run_path(str(root/'tests/integration/test_frp.py'))
    if not fixture['FRPS'] or not fixture['FRPC']:
        raise RuntimeError('Real FRP binaries required')
    runtime_class=getattr(client_runtime,'ClientRuntime',FrpRuntime)
    environment=fixture['environment'].__wrapped__(directory)
    runtimes=[];operations=Counter();accepted=set();samples=[];relay=None
    original=web.authorize
    started=time.monotonic();policy_cpu=time.process_time();policy_rss=rss_bytes()
    try:
        store,authority,server,plugin,pki,clients,session,url,port=await anext(environment)
        pid=server.process.pid
        def observe(op,content,*args):
            result=original(op,content,*args)
            operations[(op,'rejected' if result['reject'] else 'accepted')]+=1
            if op=='Login' and not result['reject']:
                host,number=content['client_address'].rsplit(':',1)
                matches={s for s in established_sockets(pid,port) if s.remote==(host,int(number))}
                if len(matches)!=1: raise RuntimeError('Unmapped accepted control')
                accepted.update(matches)
            return result
        web.authorize=observe
        for index,(credentials,_,config) in enumerate(clients):
            runtime=runtime_class(fixture['FRPC'],directory/f'owner-{index}.json')
            runtimes.append(runtime)
            await runtime.start(deepcopy(config))
            await fixture['wait_http'](session,url,credentials.domain,('alpha','bravo')[index])
        before_rss,before_cpu=process_usage(pid);peak=before_rss
        alpha=clients[0]
        for index in range(8):
            config=deepcopy(alpha[2]);config['loginFailExit']=True
            runtime=runtime_class(fixture['FRPC'],directory/f'clone-{index}.json')
            runtimes.append(runtime)
            before=sum(count for (op,_),count in operations.items() if op=='Login')
            await runtime.start(config)
            async with asyncio.timeout(5):
                while sum(count for (op,_),count in operations.items() if op=='Login')==before:
                    await asyncio.sleep(.02)
            await asyncio.sleep(.25)
            sockets=established_sockets(pid,port)
            samples.append(dict(raw=len(sockets),accepted=len(sockets&accepted),
                                unclassified=len(sockets-accepted)))
            peak=max(peak,process_usage(pid)[0])
        relay=ClientRelay(store,store.now,upstream_port=urlsplit(url).port)
        await relay.start(port=0)
        relay_url=f'http://127.0.0.1:{relay.port}'
        await fixture['wait_http'](session,relay_url,alpha[0].domain,'alpha',timeout=5)
        await fixture['wait_http'](session,relay_url,clients[1][0].domain,'bravo',timeout=5)
        await asyncio.sleep(.2)
        # Actual traffic is pending when the first client is deleted. The second
        # client's counters must still advance through the normal flush path.
        store.revoke(alpha[0].client_id)
        revision=store.access_snapshot(alpha[0].client_id,store.now())['revision']
        access=AccessService(store,relay,store.now)
        if hasattr(access,'delete_revoked'):
            await access.delete_revoked(alpha[0].client_id,revision)
        else:
            store.delete_revoked(alpha[0].client_id,revision)
        await fixture['wait_http'](session,relay_url,clients[1][0].domain,'bravo',timeout=5)
        await relay.flush()
        # Compare peer counters only where the application implements them.
        surviving=store.access_snapshot(clients[1][0].client_id,store.now())
        peer_total=surviving.get('to_client_bytes',0)+surviving.get('from_client_bytes',0)
        if hasattr(store,'admission'):
            assert all(row['accepted']==2 for row in samples), 'Duplicate/missing accepted control'
            assert peer_total>0 and relay.telemetry_error is None, 'Surviving counters failed'
        _,cpu=process_usage(pid)
        return dict(clones=8,elapsed_s=round(time.monotonic()-started,3),
            policy_cpu_s=round(time.process_time()-policy_cpu,4),policy_rss_before=policy_rss,policy_rss_peak=rss_bytes(),
            server_cpu_s=round(cpu-before_cpu,4),server_rss_before=before_rss,server_rss_peak=peak,
            accepted_control_samples=samples,peer_http=True,
            peer_total_bytes=peer_total,peer_flush_error=relay.telemetry_error,
            operations={':'.join(key):value for key,value in sorted(operations.items())})
    finally:
        web.authorize=original
        try:
            if relay is not None:
                # Measured values are already captured. Retire harness streams
                # first so an old application's wait_closed ordering cannot hang
                # cleanup on modern Python; do not alter its measured policy.
                async with asyncio.timeout(8):
                    for cid in tuple(relay.streams): await relay.disconnect(cid)
                    await relay.close()
        finally:
            await asyncio.gather(*(runtime.stop() for runtime in runtimes),return_exceptions=True)
            await environment.aclose()


async def run(root):
    with tempfile.TemporaryDirectory(prefix='ha-tunnel-frp-measure-') as directory:
        async with asyncio.timeout(120):
            return await measure(root,Path(directory))


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,default=root)
    args=parser.parse_args();source=args.source.resolve(strict=True)
    sys.path.insert(0,str(root));sys.path.insert(0,str(source))
    source_digest=runpy.run_path(str(root/'tools/performance_acceptance.py'))['source_digest']
    print(json.dumps(dict(source_sha256=source_digest(source),frp=asyncio.run(run(root))),sort_keys=True))
