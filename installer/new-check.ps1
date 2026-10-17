param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$LauncherCommit
)
$ErrorActionPreference = 'Stop'
if ($LauncherCommit -notmatch '^[a-f0-9]{40}$') { throw 'Supply the full Git commit SHA containing this launcher.' }
$secret = Read-Host 'Administrator report API token (never send it to the player)' -AsSecureString
$token = $null
try {
    $token = [Net.NetworkCredential]::new('', $secret).Password
    $session = Invoke-RestMethod -Uri 'https://anti-cheat-discord-relay.haosyy-checker.workers.dev/checks' -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body '{}'
    $code = [string]$session.check_code
    if ($code -notmatch '^[a-f0-9]{64}$') { throw 'Server did not return a valid check code.' }
    Write-Host 'Send only the following command to the player. Valid for one report within one hour.'
    Write-Host 'The command permits scripts only in its child PowerShell processes; it does not change persistent policy or override Group Policy.'
    Write-Output ("`$p = Join-Path `$env:TEMP ('cheat-checker-' + [Guid]::NewGuid().ToString('N') + '.ps1'); try { Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -Uri 'https://raw.githubusercontent.com/haosyy/checker/$LauncherCommit/installer/install.ps1' -OutFile `$p; & (Join-Path `$env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File `$p -ReleaseUrl 'https://github.com/haosyy/checker/releases/download/v2.0.0/AntiCheatChecker-win-x64.zip' -ExpectedSha256 '$ExpectedSha256' -CheckCode '$code'; if (`$LASTEXITCODE -ne 0) { throw 'Cheat Checker launcher failed. See the error above.' } } finally { Remove-Item -LiteralPath `$p -Force -ErrorAction SilentlyContinue }")
} finally {
    $token = $null
    $secret.Dispose()
}
