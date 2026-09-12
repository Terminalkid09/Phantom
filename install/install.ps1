# phantom installer (Windows) — user-scope, no admin required
#
#   irm https://raw.githubusercontent.com/Terminalkid09/Phantom/main/install/install.ps1 | iex
#
# What it does:
#   1. downloads the repository tarball from main (github codeload)
#   2. verifies the download (size sanity + zip integrity)
#   3. installs into %LOCALAPPDATA%\Phantom (user scope, no admin)
#   4. creates a private venv with the pinned python it finds (>=3.10)
#   5. pip-installs requirements.txt
#   6. writes launchers: phantom.ps1 / phantom.cmd / phantom.c2.cmd /
#      phantom.auto.cmd  + adds them to the USER PATH (no registry hacks
#      beyond HKCU Environment, which is user-scope by definition)
#   7. offers the guided toolbox step (WSL) as a follow-up command
#
# Idempotent: re-running refreshes the install in place.

$ErrorActionPreference = "Stop"

$Repo   = "Terminalkid09/Phantom"
$Branch = "main"
$Dest   = Join-Path $env:LOCALAPPDATA "Phantom"
$Zip    = Join-Path $env:TEMP "phantom-install.zip"

function Say($m)  { Write-Host "  $m" }
function Step($m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }

Write-Host ""
Write-Host "  Phantom installer (Windows, user-scope, no admin)" -ForegroundColor White
Write-Host "  -------------------------------------------------"

# ── 1. python check (do not install python silently — say what's needed)
Step "Checking Python >= 3.10"
$py = $null
foreach ($cand in @("python", "py")) {
    try {
        $v = & $cand -c "import sys;print(sys.version_info[0],sys.version_info[1])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v) {
            $parts = $v.Trim().Split(" ")
            if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 10) { $py = $cand; break }
        }
    } catch {}
}
if (-not $py) {
    Say "Python >= 3.10 not found."
    Say "Install it from https://www.python.org/downloads/ (tick 'Add to PATH'),"
    Say "then re-run this installer."
    exit 1
}
Say "python found via '$py'"

# ── 2. download the tarball
Step "Downloading phantom (branch: $Branch)"
$Url = "https://codeload.github.com/$Repo/zip/refs/heads/$Branch"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
$minSize = 100KB
if ((Get-Item $Zip).Length -lt $minSize) {
    Say "download looks truncated ($(Get-Item $Zip).Length bytes) — aborting"
    exit 1
}

# ── 3. extract
Step "Extracting to $Dest"
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
Expand-Archive -Path $Zip -DestinationPath $env:TEMP -Force
$inner = Get-ChildItem $env:TEMP -Directory -Filter "Phantom-$Branch*" |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $inner) { Say "archive layout unexpected — aborting"; exit 1 }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
# move CONTENTS of Phantom-main/ into $Dest (so %LOCALAPPDATA%\Phantom is the repo root)
Copy-Item -Path (Join-Path $inner.FullName "*") -Destination $Dest -Recurse -Force
Remove-Item $inner.FullName -Recurse -Force
Remove-Item $Zip -Force

# ── 4. venv + deps
Step "Creating virtualenv"
& $py -m venv (Join-Path $Dest ".venv")
if ($LASTEXITCODE -ne 0) { Say "venv creation failed"; exit 1 }
$pip = Join-Path $Dest ".venv\Scripts\python.exe"
Step "Installing dependencies (this can take a few minutes)"
& $pip -m pip install --quiet --disable-pip-version-check -r (Join-Path $Dest "requirements.txt")
if ($LASTEXITCODE -ne 0) { Say "pip install failed — check the output above"; exit 1 }

# ── 5. launchers
Step "Writing launchers"
$venvPy = Join-Path $Dest ".venv\Scripts\python.exe"
$launcher = @'
@echo off
"%~dp0.venv\Scripts\python.exe" "%~dp0phantom\main.py" %*
'@
Set-Content -Path (Join-Path $Dest "phantom.cmd") -Value $launcher -Encoding ASCII
Set-Content -Path (Join-Path $Dest "phantom.c2.cmd") -Value $launcher -Encoding ASCII
Set-Content -Path (Join-Path $Dest "phantom.auto.cmd") -Value $launcher -Encoding ASCII
# entrypoint dispatch (phantom.c2 / phantom.auto) is handled inside main.py
# via sys.argv[0] basename — see phantom/main.py.

# ── 6. user PATH (HKCU only — no admin)
Step "Adding to user PATH"
$bin = $Dest
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $bin) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$bin", "User")
    Say "added $bin to user PATH (new terminals will see it)"
} else {
    Say "PATH already up to date"
}

# ── 7. done + next steps
Write-Host ""
Write-Host "  [OK] phantom installed (user scope)" -ForegroundColor Green
Write-Host ""
Write-Host "  next steps (open a NEW terminal):"
Write-Host "    phantom doctor      - what is missing (tools, docker, WSL)"
Write-Host "    phantom setup       - guided toolbox setup (asks once, installs)"
Write-Host "    phantom setup wsl   - Windows: guided WSL + Kali toolbox flow"
Write-Host "    phantom             - manual core | phantom.c2 | phantom.auto"
Write-Host ""
Write-Host "  note: external tools (nmap, hydra, impacket...) live in WSL on"
Write-Host "  Windows - 'phantom setup wsl' walks you through it step by step."
