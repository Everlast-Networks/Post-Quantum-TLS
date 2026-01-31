[CmdletBinding()]
param(
  [string]$GOOS,
  [string]$GOARCH,
  [ValidateSet("0","1")]
  [string]$CGO = "0",
  [string]$Build,
  [switch]$WithKeyutil
)

$ErrorActionPreference = "Stop"

function Die([string]$msg) { throw $msg }

function Need-Command([string]$name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    Die "missing dependency: $name"
  }
}

function Go-Version-Ok {
  $v = (& go env GOVERSION) 2>$null
  if (-not $v) { return $false }
  $v = $v.Trim().Replace("go","")
  $parts = $v.Split(".")
  if ($parts.Count -lt 2) { return $false }
  $maj = [int]$parts[0]
  $min = [int]$parts[1]
  if ($maj -gt 1) { return $true }
  if ($maj -lt 1) { return $false }
  return ($min -ge 22)
}

Need-Command go

if (-not (Test-Path -Path ".\go.mod" -PathType Leaf)) {
  Die "run this from the repo root (go.mod not found)"
}

Write-Host ("Go toolchain: {0}" -f (& go env GOVERSION))
if (-not (Go-Version-Ok)) { Die "Go 1.22+ required" }

$clientPkg = ".\cmd\client"
$serverPkg = ".\cmd\server"

$clientBin = "qtls-client"
$serverBin = "qtls-server"

$clientCfgSrc = ".\config\client-example-circl.yaml"
$serverCfgSrc = ".\config\server-example-circl.yaml"

$releaseDir = ".\release"

$hostGOOS = (& go env GOOS).Trim()
$hostGOARCH = (& go env GOARCH).Trim()

if (-not $GOOS) {
  Write-Host "Select target OS (default: $hostGOOS)"
  $choices = @("windows","linux","darwin","freebsd","openbsd","netbsd","other","default")
  for ($i=0; $i -lt $choices.Count; $i++) { Write-Host ("[{0}] {1}" -f $i, $choices[$i]) }
  $sel = Read-Host "Choice"
  if ($sel -match '^\d+$' -and [int]$sel -lt $choices.Count) {
    $pick = $choices[[int]$sel]
    if ($pick -eq "default") { $GOOS = $hostGOOS }
    elseif ($pick -eq "other") { $GOOS = (Read-Host "Enter GOOS").Trim() }
    else { $GOOS = $pick }
  } else {
    $GOOS = $hostGOOS
  }
}

if (-not $GOARCH) {
  Write-Host "Select target architecture (default: $hostGOARCH)"
  $choices = @("amd64","arm64","386","arm","other","default")
  for ($i=0; $i -lt $choices.Count; $i++) { Write-Host ("[{0}] {1}" -f $i, $choices[$i]) }
  $sel = Read-Host "Choice"
  if ($sel -match '^\d+$' -and [int]$sel -lt $choices.Count) {
    $pick = $choices[[int]$sel]
    if ($pick -eq "default") { $GOARCH = $hostGOARCH }
    elseif ($pick -eq "other") { $GOARCH = (Read-Host "Enter GOARCH").Trim() }
    else { $GOARCH = $pick }
  } else {
    $GOARCH = $hostGOARCH
  }
}

$target = "$GOOS/$GOARCH"
Write-Host "Validating target: $target"

$dist = & go tool dist list
if (-not ($dist | Select-String -SimpleMatch -Quiet $target)) {
  Die "unsupported target for this Go toolchain: $target (check: go tool dist list)"
}

if (-not $Build) {
  if (Get-Command git -ErrorAction SilentlyContinue) {
    try { $Build = (& git describe --tags --always --dirty).Trim() } catch { $Build = "" }
    if (-not $Build) { $Build = (& git rev-parse --short HEAD).Trim() }
  }
  if (-not $Build) { $Build = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") }
}

$ext = ""
if ($GOOS -eq "windows") { $ext = ".exe" }

Write-Host "Preparing release tree: $releaseDir"
if (Test-Path $releaseDir) { Remove-Item -Recurse -Force $releaseDir }
New-Item -ItemType Directory -Force -Path `
  "$releaseDir\client", `
  "$releaseDir\client\config", `
  "$releaseDir\server", `
  "$releaseDir\server\config", `
  "$releaseDir\client\certs\openssl", `
  "$releaseDir\client\certs\circl", `
  "$releaseDir\server\certs\openssl", `
  "$releaseDir\server\certs\circl" | Out-Null

if (-not (Test-Path $clientCfgSrc -PathType Leaf)) { Die "missing config: $clientCfgSrc" }
if (-not (Test-Path $serverCfgSrc -PathType Leaf)) { Die "missing config: $serverCfgSrc" }

Copy-Item -Force $clientCfgSrc "$releaseDir\client\config\client.yaml"
Copy-Item -Force $serverCfgSrc "$releaseDir\server\config\server.yaml"

$clientOut = "$releaseDir\client\$clientBin$ext"
$serverOut = "$releaseDir\server\$serverBin$ext"

Write-Host "Building:"
Write-Host "  $clientOut"
Write-Host "  $serverOut"

$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED

try {
  $env:GOOS = $GOOS
  $env:GOARCH = $GOARCH
  $env:CGO_ENABLED = $CGO

  & go build -trimpath -buildvcs=false -ldflags "-X main.Build=$Build" -o $clientOut $clientPkg
  & go build -trimpath -buildvcs=false -ldflags "-X main.Build=$Build" -o $serverOut $serverPkg

  if ($WithKeyutil) {
    $keyutilPkg = ".\cmd\keyutil"
    $keyutilOutDir = "$releaseDir\tools"
    New-Item -ItemType Directory -Force -Path $keyutilOutDir | Out-Null
    & go build -trimpath -buildvcs=false -o "$keyutilOutDir\qtls-keyutil$ext" $keyutilPkg
  }
}
finally {
  $env:GOOS = $oldGOOS
  $env:GOARCH = $oldGOARCH
  $env:CGO_ENABLED = $oldCGO
}

Write-Host ""
Write-Host "Done."
Write-Host ("Target:      {0}" -f $target)
Write-Host ("Build tag:   {0}" -f $Build)
Write-Host ("Release dir: {0}" -f $releaseDir)
