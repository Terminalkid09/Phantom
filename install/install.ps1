# phantom installer (Windows) — user-scope, no admin required
#
#   irm https://raw.githubusercontent.com/Terminalkid09/Phantom/main/install/install.ps1 | iex
#
# What it does:
#   1. downloads the repository tarball from the BRANCH you chose (github
#      codeload; `dev` by default — the line these docs describe — override
#      with $env:PHANTOM_BRANCH = 'main' for the released line)
#   2. verifies the download (size sanity + zip integrity + the files the
#      installer is about to rely on)
#   3. installs into %LOCALAPPDATA%\Phantom (user scope, no admin) — the files
#      the framework needs, not the whole working tree
#      (set $env:PHANTOM_FULL_TREE = 1 for the old whole-tree copy)
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
$Branch = if ($env:PHANTOM_BRANCH) { $env:PHANTOM_BRANCH } else { "dev" }
$Dest   = Join-Path $env:LOCALAPPDATA "Phantom"
$Zip    = Join-Path $env:TEMP "phantom-install.zip"
$FullTree = ($env:PHANTOM_FULL_TREE -eq "1")

# What a run needs: the package (code + payloads + exploits), the packaging
# metadata, the requirement list, the licence/readme. Everything else (docs,
# tests, the Electron app) is the repository, not the product.
$Keep = @("phantom", "setup.py", "MANIFEST.in", "requirements.txt",
          "README.md", "LICENSE")

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
Step "Installing to $Dest (branch: $Branch)"
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
Expand-Archive -Path $Zip -DestinationPath $env:TEMP -Force
$inner = Get-ChildItem $env:TEMP -Directory -Filter "Phantom-$Branch*" |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $inner) { Say "archive layout unexpected — aborting"; exit 1 }
# the archive must actually contain what this script is about to rely on:
# "it downloaded" and "it is the right thing" are different claims
foreach ($needed in @("phantom\main.py", "requirements.txt", "setup.py")) {
    if (-not (Test-Path (Join-Path $inner.FullName $needed))) {
        Say "this archive has no $needed — wrong branch ($Branch) or a partial tag?"
        Say "try: `$env:PHANTOM_BRANCH = 'main'; rerun the installer"
        exit 1
    }
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
if ($FullTree) {
    Say "PHANTOM_FULL_TREE=1: copying the whole tree (old behaviour)"
    Copy-Item -Path (Join-Path $inner.FullName "*") -Destination $Dest -Recurse -Force
} else {
    foreach ($item in $Keep) {
        $source = Join-Path $inner.FullName $item
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $Dest -Recurse -Force
        }
    }
}
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
Write-Host "  [OK] phantom installed from branch $Branch (user scope)" -ForegroundColor Green
Write-Host "       $Dest"
Write-Host ""
Write-Host "  next steps (open a NEW terminal):"
Write-Host "    phantom doctor      - what is missing (tools, docker, WSL)"
Write-Host "    phantom setup       - guided toolbox setup (asks once, installs)"
Write-Host "    phantom setup wsl   - Windows: guided WSL + Kali toolbox flow"
Write-Host "    phantom             - manual core | phantom.c2 | phantom.auto"
Write-Host ""
Write-Host "  note: external tools (nmap, hydra, impacket...) live in WSL on"
Write-Host "  Windows - 'phantom setup wsl' walks you through it step by step."
