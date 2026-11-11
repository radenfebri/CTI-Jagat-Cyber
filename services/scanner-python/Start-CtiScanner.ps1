[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Token,

    [switch] $Install
)

$ErrorActionPreference = 'Stop'
$serviceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvRoot = Join-Path $serviceRoot '.venv'
$pythonPath = Join-Path $venvRoot 'Scripts\python.exe'
$requirementsPath = Join-Path $serviceRoot 'requirements.txt'

Set-Location -LiteralPath $serviceRoot

if (-not (Test-Path -LiteralPath $pythonPath)) {
    & python -m venv $venvRoot
}

if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Python virtual environment was not created at $pythonPath"
}

if ($Install) {
    & $pythonPath -m pip install --upgrade pip
    & $pythonPath -m pip install --requirement $requirementsPath
}

$env:CTI_WORKER_TOKEN = $Token
& $pythonPath -m uvicorn scanner_service.main:app --host 127.0.0.1 --port 9100
