"""Verify a trusted Ingress identity against Home Assistant's actual users."""
import aiohttp
import asyncio


async def verified_admin(user_id,supervisor_token):
    if not isinstance(user_id,str) or not user_id or len(user_id)>128 or not supervisor_token: return False
    try:
        async with asyncio.timeout(5), aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5),trust_env=False) as session:
            async with session.ws_connect('http://supervisor/core/websocket',max_msg_size=65536) as ws:
                if (await ws.receive_json())['type']!='auth_required': return False
                await ws.send_json({'type':'auth','access_token':supervisor_token})
                if (await ws.receive_json())['type']!='auth_ok': return False
                await ws.send_json({'id':1,'type':'config/auth/list'})
                result=await ws.receive_json()
                if result.get('id')!=1 or result.get('success') is not True or not isinstance(result.get('result'),list): return False
                return any(isinstance(user,dict) and user.get('id')==user_id and
                    user.get('is_active') is True and not user.get('system_generated') and
                    (user.get('is_owner') is True or 'system-admin' in user.get('group_ids',[]))
                    for user in result['result'])
    except Exception: return False
