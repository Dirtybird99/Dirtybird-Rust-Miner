# Fair serial head-to-head: this Rust miner vs the canonical Dirtybird C miner.
#
# Methodology (the one that produced the published numbers):
#   * ONE miner at a time (never concurrent) — no cross-miner resource contention.
#   * ALTERNATING run-order each round, so neither side always lands on the hotter
#     chip (removes the "first runner gets the cooler CPU" confound).
#   * Both processes forced to HIGH priority (symmetric).
#   * Rust = the dual-PGO + cross-language-LTO winning binary, `--sustained` (unpinned).
#     C   = the canonical PGO binary from build-pgo-use (NOT the slow build/ tree).
#         Dirtybird has no working thread affinity on Windows, so it runs unpinned too.
#   * Reports per-round KH/s + delta + winner, then averages and the round-win count.
#
# NOTE: the two measurement tools differ (Rust `--sustained` vs C `pgo-train`), so a
# sub-1% delta is inside cross-tool uncertainty — read the round-win count, not just
# the average. The big margin to trust is vs the Rust competitor (see BENCHMARKS.md).
#
# Usage: pwsh -File headtohead.ps1 [sampleSecs] [rounds] [threads] [cBinDir] [rustExe]
param(
  [int]$sample  = 30,
  [int]$rounds  = 8,
  [int]$threads = 24,
  [string]$cBinDir = "C:\Users\allen\Desktop\Dirtybird-C-Miner\build-pgo-use\bin",
  [string]$rustExe = "target\x86_64-pc-windows-msvc\release-lto\dero-miner.exe"
)
$ErrorActionPreference = "Continue"
$c = Join-Path $cBinDir "dirtybird-pgo-train.exe"
if (-not (Test-Path $rustExe)) { Write-Error "rust miner missing: $rustExe"; exit 1 }
if (-not (Test-Path $c))       { Write-Error "canonical C miner missing: $c"; exit 1 }

function Run-Proc($exe, $argList, $workdir) {
  $tmp = [System.IO.Path]::GetTempFileName()
  $sp = @{ FilePath=$exe; ArgumentList=$argList; NoNewWindow=$true; PassThru=$true; RedirectStandardOutput=$tmp }
  if ($workdir) { $sp.WorkingDirectory = $workdir }
  $p = Start-Process @sp
  try { $p.PriorityClass = 'High' } catch {}
  $p.WaitForExit()
  return (Get-Content $tmp -Raw)
}
function Run-Rust([int]$t, [int]$s) {
  $o = Run-Proc $rustExe @("--sustained","-t","$t","--secs","$s") $null
  if ($o -match 'HASHRATE\s*:\s*([\d.]+)\s*H/s') { return [double]$Matches[1] / 1000.0 }
  return 0.0
}
function Run-C([int]$t, [int]$s) {
  $o = Run-Proc $c @("-t","$t","--seconds","$s","--difficulty","1000000000","--rotate-ms","9000") $cBinDir
  # output has two 'hashes=' tokens (config echo + result); anchor on the result line
  if ($o -match 'pgo_train\s+hashes=([0-9]+)') { return [double]$Matches[1] / $s / 1000.0 }
  return 0.0
}

Write-Host "warmup 20s (thermal steady-state)..."; [void](Run-Rust $threads 20)
$rVals = @(); $cVals = @(); $rWins = 0; $cWins = 0; $ties = 0
for ($i = 1; $i -le $rounds; $i++) {
  if ($i % 2 -eq 1) { $a = Run-Rust $threads $sample; Start-Sleep -Seconds 3; $b = Run-C $threads $sample }
  else              { $b = Run-C    $threads $sample; Start-Sleep -Seconds 3; $a = Run-Rust $threads $sample }
  Start-Sleep -Seconds 3
  $rVals += $a; $cVals += $b
  $w = if ([math]::Abs($a-$b) -lt 0.05) { $ties++; "tie" } elseif ($a -gt $b) { $rWins++; "RUST" } else { $cWins++; "C" }
  Write-Host ("round {0}:  RUST {1,6:N2}   C {2,6:N2}   delta {3,7:N2}%   winner {4}" -f $i,$a,$b,(($a-$b)/$b*100),$w)
}
$rAvg = [math]::Round((($rVals | Measure-Object -Average).Average), 2)
$cAvg = [math]::Round((($cVals | Measure-Object -Average).Average), 2)
$d    = [math]::Round((($rAvg-$cAvg)/$cAvg*100), 2)
Write-Host "`n=========== HEAD-TO-HEAD ($threads`T, $rounds rounds, serial, alternating, HIGH) ==========="
Write-Host ("RUST avg   : $rAvg KH/s")
Write-Host ("C    avg   : $cAvg KH/s   (canonical build-pgo-use PGO binary)")
Write-Host ("DELTA      : $d %  (Rust vs C)")
Write-Host ("round wins : RUST=$rWins  C=$cWins  ties=$ties")
