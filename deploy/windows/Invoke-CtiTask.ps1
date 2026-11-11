[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PhpPath,
    [Parameter(Mandatory)][ValidateSet('Scheduler', 'Worker')][string] $Mode
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artisan = Join-Path $projectRoot 'artisan'
$logDirectory = Join-Path $projectRoot 'storage\logs'
$log = Join-Path $logDirectory ('cti-{0}-{1}.log' -f $Mode.ToLowerInvariant(), (Get-Date -Format 'yyyy-MM-dd'))

if ($Mode -eq 'Scheduler') {
    $arguments = @($artisan, 'schedule:run', '--no-interaction')
} else {
    $arguments = @($artisan, 'queue:work', '--queue=cti', '--stop-when-empty', '--max-time=50', '--sleep=1', '--timeout=60', '--no-interaction')
}

Push-Location -LiteralPath $projectRoot
try {
    $ErrorActionPreference = 'Continue'
    & $PhpPath @arguments 2>&1 | Out-File -LiteralPath $log -Append -Encoding utf8
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $exitCode
