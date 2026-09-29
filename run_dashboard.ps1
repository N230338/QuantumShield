$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
& .\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --port 8000
