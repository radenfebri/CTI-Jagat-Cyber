[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $PhpPath = (Get-Command php.exe -CommandType Application -ErrorAction Stop).Source,
    [ValidatePattern('^[A-Za-z0-9 _.-]+$')][string] $TaskPrefix = 'CTI-Jagat-Cyber',
    [pscredential] $Credential
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$phpExecutable = (Resolve-Path -LiteralPath $PhpPath).Path
$launcher = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'Invoke-CtiTask.ps1')).Path
$powershell = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
$description = "CTI Jagat Cyber passive automation | $projectRoot"

if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'artisan') -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $projectRoot '.env') -PathType Leaf)) {
    throw 'The project must have an artisan entry point and a configured .env.'
}

foreach ($mode in @('Scheduler', 'Worker')) {
    $existing = Get-ScheduledTask -TaskName "$TaskPrefix-$mode" -TaskPath '\' -ErrorAction SilentlyContinue
    if ($existing -and $existing.Description -ne $description) {
        throw "Task $TaskPrefix-$mode already exists and belongs to another setup. Choose a different -TaskPrefix."
    }
}

$startsAt = (Get-Date).AddMinutes(1)
$trigger = New-ScheduledTaskTrigger -Once -At $startsAt -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

foreach ($mode in @('Scheduler', 'Worker')) {
    $name = "$TaskPrefix-$mode"
    $arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -PhpPath "{1}" -Mode {2}' -f $launcher, $phpExecutable, $mode
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $projectRoot
    $definition = @{
        TaskName = $name
        TaskPath = '\'
        Action = $action
        Trigger = $trigger
        Settings = $settings
        Description = $description
        Force = $true
    }

    if ($PSCmdlet.ShouldProcess($name, 'Register repeating CTI task')) {
        if ($Credential) {
            Register-ScheduledTask @definition -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -RunLevel Limited | Out-Null
        } else {
            $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask @definition -Principal $principal | Out-Null
        }
        Write-Output "Registered $name"
    }
}
