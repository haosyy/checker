param(
    [Parameter(Mandatory = $true)][string]$ReleaseUrl,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
$temp = Join-Path ([IO.Path]::GetTempPath()) ("anti-cheat-checker-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$exePath = Join-Path $temp 'AntiCheatChecker.exe'

try
{
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $exePath -UseBasicParsing
    $actualHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash

    if ($actualHash -ne $ExpectedSha256.ToUpperInvariant())
    {
        throw "SHA-256 mismatch. Expected: $ExpectedSha256; actual: $actualHash"
    }

    Start-Process -FilePath $exePath -WorkingDirectory $temp -Verb RunAs -Wait
}
finally
{
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}