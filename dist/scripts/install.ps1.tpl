# Anywhere-Port Installer for Windows
$ErrorActionPreference = "Stop"

$Master = "{{.MasterAddr}}"
$ID = "{{.AgentID}}"
$Token = "{{.Token}}"
$DownloadUrl = "{{.DownloadUrl}}/awport-agent.exe"

Write-Host "Anywhere-Port Agent Installer" -ForegroundColor Cyan
Write-Host "-----------------------------"
Write-Host "Master: $Master"
Write-Host "ID:     $ID"

# 1. 创建目录
$InstallDir = "anywhere-port"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}
Set-Location $InstallDir

# 2. 下载 Agent
Write-Host "Downloading agent from $DownloadUrl..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile "awport-agent.exe" -UseBasicParsing
} catch {
    Write-Error "Failed to download agent: $_"
    exit 1
}

# 3. 生成启动脚本
$BatFile = "start_agent_$ID.bat"
$CmdContent = "@echo off
cd /d ""%~dp0""
start /b awport-agent.exe -master $Master -id $ID -token $Token"
Set-Content -Path $BatFile -Value $CmdContent

Write-Host "Setup complete."
Write-Host "Run '$BatFile' to start." -ForegroundColor Green
