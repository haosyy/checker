param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PlayerKey
)
$ErrorActionPreference = 'Stop'
$repo = 'haosyy/checker'
$assetName = 'AntiCheatChecker-win-x64.zip'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $PSCommandPath) { throw 'Run the saved launcher file.' }
    $scriptLiteral = $PSCommandPath.Replace("'", "''")
    $command = "try { & '$scriptLiteral' -PlayerKey '$PlayerKey'; exit 0 } catch { Write-Error -ErrorRecord `$_ -ErrorAction Continue; Read-Host 'Press Enter to close'; exit 1 }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child = Start-Process -FilePath $ps -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded" -PassThru
    try {
        $childHandle = $child.Handle
        $child.WaitForExit()
        $childExitCode = $child.ExitCode
        if ($null -eq $childExitCode) {
            Write-Warning 'Elevated launcher exit code unavailable. Check the checker window and Discord delivery result.'
        } elseif ($childExitCode -ne 0) {
            throw "Elevated launcher failed with code $childExitCode."
        }
    } finally { $child.Dispose() }
    return
}
$headers = @{ 'User-Agent' = 'cheat-checker-launcher'; 'Accept' = 'application/vnd.github+json' }
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $headers -UseBasicParsing
$asset = @($release.assets | Where-Object { $_.name -eq $assetName })[0]
if (-not $asset) { throw "Release asset $assetName not found in the latest release." }
$ReleaseUrl = [string]$asset.browser_download_url
$uri = [Uri]$ReleaseUrl
if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com' -or -not $uri.AbsolutePath.StartsWith("/$repo/releases/download/", [StringComparison]::Ordinal)) {
    throw 'Unexpected release URL.'
}
$ExpectedSha256 = $null
if ([string]$asset.digest -match '^sha256:([A-Fa-f0-9]{64})$') { $ExpectedSha256 = $Matches[1].ToLowerInvariant() }
if (-not $ExpectedSha256) {
    $sums = (Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$repo/releases/latest/download/checksums.txt").Content
    $line = @($sums -split "`r?`n" | Where-Object { $_ -match [Regex]::Escape($assetName) })[0]
    if (-not $line) { throw 'checksums.txt has no entry for the release asset.' }
    $candidate = ($line -split '\s+')[0]
    if ($candidate -match '^[A-Fa-f0-9]{64}$') { $ExpectedSha256 = $candidate.ToLowerInvariant() }
}
if (-not $ExpectedSha256) { throw 'Could not determine the release SHA-256.' }
$temp = $null
$previousToken = [Environment]::GetEnvironmentVariable('REPORT_API_TOKEN', 'Process')
try {
    $temp = Join-Path ([IO.Path]::GetTempPath()) ('cheat-checker-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp | Out-Null
    $zip = Join-Path $temp 'checker.zip'
    $app = Join-Path $temp 'app'
    Write-Host "Downloading Cheat Checker $($release.tag_name)..."
    & curl.exe --location --fail --show-error --progress-bar --proto '=https' --proto-redir '=https' --output $zip $ReleaseUrl
    if ($LASTEXITCODE -ne 0) { throw 'Download failed.' }
    $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256.ToUpperInvariant()) { throw "SHA-256 mismatch. Expected: $ExpectedSha256; actual: $actual" }
    Expand-Archive -LiteralPath $zip -DestinationPath $app -Force
    $executables = @(Get-ChildItem -LiteralPath $app -Recurse -File -Filter 'AntiCheat.Client.exe')
    if ($executables.Count -ne 1) { throw 'Expected exactly one AntiCheat.Client.exe.' }
    $exe = $executables[0]
    $rulesPath = Join-Path $exe.DirectoryName 'rules.json'
    $rules = Get-Content -LiteralPath $rulesPath -Raw | ConvertFrom-Json
    if ($rules.reportApiUrl -ne 'https://anti-cheat-discord-relay.haosyy-checker.workers.dev/report') { throw 'Unexpected report API URL.' }
    if (-not (Test-Path -LiteralPath (Join-Path $exe.DirectoryName 'indicators.json'))) { throw 'indicators.json missing.' }
    Write-Host 'Voluntary check: configured findings, computer name and user name are sent to the administrator.'
    [Environment]::SetEnvironmentVariable('REPORT_API_TOKEN', $PlayerKey, 'Process')
    $process = Start-Process -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName -NoNewWindow -PassThru
    try {
        $processHandle = $process.Handle
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        if ($null -eq $exitCode) {
            Write-Warning 'Checker exit code unavailable. Check the report delivery result in the checker window or Discord.'
        } elseif ($exitCode -ne 0) {
            throw "Checker exited with code $exitCode."
        }
    } finally { $process.Dispose() }
} finally {
    [Environment]::SetEnvironmentVariable('REPORT_API_TOKEN', $previousToken, 'Process')
    if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}
