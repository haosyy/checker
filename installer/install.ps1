param(
    [Parameter(Mandatory = $true)][string]$ReleaseUrl,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
$temp = Join-Path ([IO.Path]::GetTempPath()) ("cheat-checker-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$zipPath = Join-Path $temp 'CheatChecker.zip'

try
{
    & curl.exe -L --fail --silent --show-error -o $zipPath $ReleaseUrl
    if ($LASTEXITCODE -ne 0)
    {
        throw "Download failed with curl exit code $LASTEXITCODE"
    }

    $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash

    if ($actualHash -ne $ExpectedSha256.ToUpperInvariant())
    {
        throw "SHA-256 mismatch. Expected: $ExpectedSha256; actual: $actualHash"
    }

    Expand-Archive -LiteralPath $zipPath -DestinationPath $temp -Force
    $exe = Get-ChildItem -LiteralPath $temp -Recurse -Filter *.exe | Select-Object -First 1

    if ($null -eq $exe)
    {
        throw "Executable file was not found in the downloaded archive."
    }

    Start-Process -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName -Verb RunAs -Wait
}
finally
{
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}