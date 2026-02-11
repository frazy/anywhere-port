# Anywhere-Port Agent Installer for Windows
$ErrorActionPreference = "Stop"

$Master = "{{.MasterAddr}}"
$ID = "{{.AgentID}}"
$Token = "{{.Token}}"
$DownloadUrl = "{{.DownloadUrl}}/awport-agent.exe"

Write-Host "Anywhere-Port Agent Installer" -ForegroundColor Cyan
Write-Host "-----------------------------"
Write-Host "Master: $Master"
Write-Host "ID:     $ID"

# 1. Setup directory
$InstallDir = "$env:USERPROFILE\anywhere-port"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}
Set-Location $InstallDir

# 2. Stop old agent if running
$existing = Get-Process -Name "awport-agent" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Stopping old agent (PID: $($existing.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $existing.Id -Force
    Start-Sleep -Seconds 2
}

# 3. Download Agent
Write-Host "Downloading agent from $DownloadUrl..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile "awport-agent.exe" -UseBasicParsing
} catch {
    Write-Error "Failed to download agent: $_"
    exit 1
}

# Verify download
if ((Get-Item "awport-agent.exe").Length -lt 1024) {
    Write-Error "Downloaded file is too small, likely failed."
    Remove-Item "awport-agent.exe" -Force
    exit 1
}

# 4. Generate startup script with duplicate check
$BatFile = "start_agent_$ID.bat"
$CmdContent = @"
@echo off
cd /d "%~dp0"
tasklist /FI "IMAGENAME eq awport-agent.exe" 2>nul | find "awport-agent.exe" >nul && (
    echo Agent is already running.
    pause
    exit /b 0
)
start /b awport-agent.exe -master $Master -id $ID -token $Token
echo Agent started.
"@
Set-Content -Path $BatFile -Value $CmdContent -Encoding ASCII

# 5. Start agent now
Write-Host "[*] Starting agent..." -ForegroundColor Yellow
Start-Process -FilePath ".\awport-agent.exe" `
    -ArgumentList "-master", $Master, "-id", $ID, "-token", $Token `
    -WindowStyle Hidden

Start-Sleep -Seconds 1
$proc = Get-Process -Name "awport-agent" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "[+] Agent started (PID: $($proc.Id))" -ForegroundColor Green
} else {
    Write-Host "[-] Agent may have failed to start." -ForegroundColor Red
    exit 1
}
