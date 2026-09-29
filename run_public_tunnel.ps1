$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$cloudflared = Join-Path $PSScriptRoot "cloudflared.exe"
if (!(Test-Path $cloudflared)) {
    $cloudflaredCmd = Get-Command cloudflared.exe -ErrorAction SilentlyContinue
    if ($cloudflaredCmd) {
        $cloudflared = $cloudflaredCmd.Source
    } else {
        Write-Host "Downloading cloudflared..." -ForegroundColor Cyan
        curl.exe -L -o $cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
    }
}

Write-Host "Starting Cloudflare Quick Tunnel for QuantumShield (http://127.0.0.1:8000)..." -ForegroundColor Cyan
& $cloudflared tunnel --url http://127.0.0.1:8000
