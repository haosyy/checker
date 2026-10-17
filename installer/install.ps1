param(
    [Parameter(Mandatory = $true)][string]$ReleaseUrl,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [string]$ReportApiToken
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    if (-not [string]::IsNullOrEmpty($ReportApiToken)) {
        throw 'Run from an administrator PowerShell with ReportApiToken, or omit ReportApiToken to enter it securely after UAC.'
    }
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Save this launcher as a .ps1 file before running it.'
    }
    $scriptLiteral = $PSCommandPath.Replace("'", "''")
    $urlLiteral = $ReleaseUrl.Replace("'", "''")
    $command = "try { & '$scriptLiteral' -ReleaseUrl '$urlLiteral' -ExpectedSha256 '$ExpectedSha256'; exit 0 } catch { Write-Error -ErrorRecord `$_ -ErrorAction Continue; Read-Host 'Press Enter to close'; exit 1 }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList "-NoProfile -EncodedCommand $encoded" -Wait -PassThru
    if ($child.ExitCode -ne 0) { throw "Elevated launcher failed with exit code $($child.ExitCode)." }
    return
}

$uri = [Uri]$ReleaseUrl
if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com' -or -not $uri.AbsolutePath.StartsWith('/haosyy/checker/releases/download/', [StringComparison]::Ordinal)) {
    throw 'ReleaseUrl must point to an HTTPS release asset in haosyy/checker.'
}

$previousToken = [Environment]::GetEnvironmentVariable('REPORT_API_TOKEN', 'Process')
$temp = $null
$secureToken = $null
try {
    if ([string]::IsNullOrWhiteSpace($ReportApiToken)) {
        $secureToken = Read-Host 'Report API token (hidden input)' -AsSecureString
        $ReportApiToken = [Net.NetworkCredential]::new('', $secureToken).Password
    }
    if ([string]::IsNullOrWhiteSpace($ReportApiToken)) { throw 'Report API token is empty.' }

    $temp = Join-Path ([IO.Path]::GetTempPath()) ('cheat-checker-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp | Out-Null
    $zipPath = Join-Path $temp 'CheatChecker.zip'
    $appPath = Join-Path $temp 'app'
    Write-Host 'Downloading Cheat Checker...'
    & curl.exe --location --fail --show-error --progress-bar --proto '=https' --proto-redir '=https' --output $zipPath $ReleaseUrl
    if ($LASTEXITCODE -ne 0) { throw "Download failed with curl exit code $LASTEXITCODE" }

    $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    if ($actualHash -ne $ExpectedSha256) {
        throw "SHA-256 mismatch. Expected: $ExpectedSha256; actual: $actualHash"
    }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $appPath -Force
    $executables = @(Get-ChildItem -LiteralPath $appPath -Recurse -File -Filter 'AntiCheat.Client.exe')
    if ($executables.Count -ne 1) { throw 'Expected exactly one AntiCheat.Client.exe in the archive.' }
    $exe = $executables[0]
    $rulesPath = Join-Path $exe.DirectoryName 'rules.json'
    $indicatorsPath = Join-Path $exe.DirectoryName 'indicators.json'
    if (-not (Test-Path -LiteralPath $rulesPath -PathType Leaf)) { throw 'rules.json is missing.' }
    if (-not (Test-Path -LiteralPath $indicatorsPath -PathType Leaf)) { throw 'indicators.json is missing.' }
    $rules = Get-Content -LiteralPath $rulesPath -Raw | ConvertFrom-Json
    if ($rules.reportApiUrl -ne 'https://anti-cheat-discord-relay.haosyy-checker.workers.dev/report') {
        throw 'Unexpected report API URL in rules.json.'
    }

    [Environment]::SetEnvironmentVariable('REPORT_API_TOKEN', $ReportApiToken, 'Process')
    Write-Host 'Starting voluntary check. The report includes the configured scan findings, computer name and user name.'
    $process = Start-Process -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName -NoNewWindow -PassThru
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Checker exited with code $($process.ExitCode)." }
}
finally {
    [Environment]::SetEnvironmentVariable('REPORT_API_TOKEN', $previousToken, 'Process')
    $ReportApiToken = $null
    if ($null -ne $secureToken) { $secureToken.Dispose() }
    if ($temp -and (Test-Path -LiteralPath $temp)) {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
