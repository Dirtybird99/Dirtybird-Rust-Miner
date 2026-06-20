# Benchmark the real Dirtybird C miner (offline) across thread counts, for the
# head-to-head vs the Rust miner. Dirtybird has NO thread affinity (runs N
# threads unpinned), so its only knob is thread count (+ HIGH priority, which we
# set to match the Rust --sustained default for a fair comparison).
#
# Usage: powershell -ExecutionPolicy Bypass -File dirtybird_bench.ps1 [secs]
param([int]$secs = 60)

$ErrorActionPreference = "Stop"
$bindir = "C:\Users\allen\Desktop\Dirtybird-C-Miner\build-pgo-use\bin"
$bin = Join-Path $bindir "dirtybird-pgo-train.exe"
if (-not (Test-Path $bin)) { Write-Error "Dirtybird binary missing: $bin"; exit 1 }

$threads = @(8, 16, 20, 24)
$results = @()
foreach ($t in $threads) {
  Write-Host "`n>>> Dirtybird -t $t  (secs=$secs, HIGH prio, unpinned)"
  $tmp = [System.IO.Path]::GetTempFileName()
  $p = Start-Process -FilePath $bin `
        -ArgumentList @("-t","$t","--seconds","$secs","--difficulty","1000000000","--rotate-ms","9000") `
        -WorkingDirectory $bindir -NoNewWindow -PassThru -RedirectStandardOutput $tmp
  try { $p.PriorityClass = 'High' } catch { Write-Host "  (could not set High priority)" }
  $p.WaitForExit()
  $out = Get-Content $tmp -Raw
  Remove-Item $tmp -ErrorAction SilentlyContinue
  # NOTE: output has TWO 'hashes=' tokens — the config echo ('hashes=0', the
  # --hashes cap) and the RESULT line 'pgo_train hashes=N'. Anchor on the latter.
  $n = 0.0
  if ($out -match 'pgo_train\s+hashes=(\d+)') { $n = [double]$Matches[1] }
  $khs = if ($secs -gt 0) { $n / $secs / 1000.0 } else { 0.0 }
  Write-Host ("  hashes={0}  =>  {1:N2} KH/s" -f $n, $khs)
  $results += [pscustomobject]@{ Threads=$t; KHs=[math]::Round($khs,2); Hashes=$n }
}

Write-Host "`n=============== DIRTYBIRD SWEEP SUMMARY (KH/s) ==============="
$results | Sort-Object KHs -Descending | Format-Table -AutoSize
$best = ($results | Sort-Object KHs -Descending | Select-Object -First 1)
Write-Host ("DIRTYBIRD BEST: -t {0} @ {1:N2} KH/s" -f $best.Threads, $best.KHs)
