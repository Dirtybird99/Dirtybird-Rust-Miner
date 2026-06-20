# Thread/affinity/thermal sweep for the AstroBWTv3 miner.
# The crux "beat Dirtybird" experiment: Dirtybird runs all 24 logical with NO
# affinity. On a thermal-limited 13700HX laptop, peak SUSTAINED throughput is
# usually fewer P-pinned threads. We can pin + pick thread count; Dirtybird can't.
#
# Usage: powershell -ExecutionPolicy Bypass -File sweep.ps1 [secs]
param([int]$secs = 60)

# NOTE: keep this 'Continue' — the miner writes status lines to stderr, and with
# 'Stop' + 2>&1 PowerShell turns the first stderr line into a terminating error.
$ErrorActionPreference = "Continue"
$bin = "target\release-lto\dero-miner.exe"
if (-not (Test-Path $bin)) { Write-Error "build first: $bin missing"; exit 1 }

# 13700HX: logical 0-15 = 8 P-cores (HT pairs, primaries even), 16-23 = 8 E-cores.
$P_PRIMARY = "0,2,4,6,8,10,12,14"
$P_ALL     = "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
$P_PRI_E   = "0,2,4,6,8,10,12,14,16,17,18,19,20,21,22,23"
$ALL24     = (0..23) -join ","

# name; threads; pin(bool); PIN_CORES (empty = no pin)
$configs = @(
  @{n="08T P-primary (no HT), pinned"; t=8;  pin=$true;  cores=$P_PRIMARY},
  @{n="16T P-cores+HT, pinned";        t=16; pin=$true;  cores=$P_ALL},
  @{n="16T P-primary+8E, pinned";      t=16; pin=$true;  cores=$P_PRI_E},
  @{n="20T no-pin (Dirtybird claim)";  t=20; pin=$false; cores=""},
  @{n="24T no-pin (Dirtybird style)";  t=24; pin=$false; cores=""},
  @{n="24T all-pinned";                t=24; pin=$true;  cores=$ALL24}
)

$results = @()
foreach ($c in $configs) {
  Write-Host "`n==================================================================="
  Write-Host ">>> $($c.n)  (t=$($c.t), pin=$($c.pin), secs=$secs)"
  if ($c.cores -ne "") { $env:PIN_CORES = $c.cores } else { Remove-Item Env:\PIN_CORES -ErrorAction SilentlyContinue }
  $pinArg = if ($c.pin) { "--pin" } else { $null }
  $args = @("--sustained", "-t", "$($c.t)", "--secs", "$secs")
  if ($pinArg) { $args += $pinArg }
  $out = & $bin @args 2>&1 | Out-String
  $hr = ($out -split "`n" | Select-String -Pattern "HASHRATE").Line
  $pt = ($out -split "`n" | Select-String -Pattern "per-thread").Line
  Write-Host $hr
  Write-Host $pt
  $khs = if ($hr -match '\(([\d.]+) KH/s\)') { [double]$Matches[1] } else { 0.0 }
  $results += [pscustomobject]@{ Config=$c.n; KHs=$khs }
}
Remove-Item Env:\PIN_CORES -ErrorAction SilentlyContinue

Write-Host "`n=================== SWEEP SUMMARY (KH/s) ==========================="
$results | Sort-Object KHs -Descending | Format-Table -AutoSize
$best = ($results | Sort-Object KHs -Descending | Select-Object -First 1)
Write-Host ("BEST: {0} @ {1:N2} KH/s" -f $best.Config, $best.KHs)
Write-Host "Dirtybird claim: ~20 KH/s @ 20T on this CPU."
