# A/B the v114 descriptor SA backends: pure-Rust (default) vs vendored C++
# (DERO_V114_CPP=1). ONE binary, one backend per run, alternating order each
# round so neither side always runs on the hotter chip -- the BENCHMARKS.md
# methodology, applied within a single build.
#
#   .\v114_ab.ps1 [-Seconds 30] [-Threads 24] [-Rounds 8]
#
# Reports per-round KH/s, the mean delta, and a sign test over decided rounds.
# The gate: Rust must be within measurement noise of C++ (see BENCHMARKS.md,
# which treats a sub-1% cross-tool delta as parity).

param(
    [int]$Seconds = 30,
    [int]$Threads = 24,
    [int]$Rounds  = 8,
    [ValidateSet('release', 'release-lto')]
    [string]$Profile = 'release'
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot "target\$Profile\dero-miner.exe"
if (-not (Test-Path $exe)) {
    throw "missing $exe -- build it with BOTH backends compiled in:`n" +
          "  cargo build --profile $Profile -p dero-miner --features v114-cpp"
}
# A stale or half-relinked exe silently produces nonsense (a locked binary makes
# cargo fail AFTER leaving an old one in place). Refuse to measure it.
if (Get-Process -Name 'dero-miner' -ErrorAction SilentlyContinue) {
    throw 'dero-miner is already running -- kill it before measuring'
}
$age = (Get-Date) - (Get-Item $exe).LastWriteTime
Write-Host ("binary: {0}  ({1:N1} min old)" -f $exe, $age.TotalMinutes)

function Invoke-Backend {
    param([string]$Backend)

    # `v114-cpp` builds only: without it the C++ is not compiled and
    # DERO_V114_CPP is ignored, which would silently measure Rust twice.
    if ($Backend -eq 'cpp') { $env:DERO_V114_CPP = '1' } else { Remove-Item Env:\DERO_V114_CPP -ErrorAction SilentlyContinue }

    $p = Start-Process -FilePath $exe `
        -ArgumentList '--sustained', '--secs', $Seconds, '-t', $Threads `
        -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\v114_ab_$Backend.txt"
    $p.PriorityClass = 'High'
    $p.WaitForExit()

    $out = Get-Content "$env:TEMP\v114_ab_$Backend.txt" -Raw
    # sustained.rs prints "HASHRATE       : <n> H/s  (<n> KH/s)" as its summary.
    # Anchor on that line: the interval trace also contains KH/s values.
    if ($out -match 'HASHRATE\s*:\s*[\d.]+\s*H/s\s*\(([\d.]+)\s*KH/s\)') { return [double]$Matches[1] }
    Write-Host $out
    throw "could not parse throughput for backend=$Backend"
}

Write-Host "v114 backend A/B -- $Profile, $Threads threads, ${Seconds}s window, $Rounds rounds`n"
Write-Host ('{0,-6} {1,9} {2,9} {3,9}  {4}' -f 'round', 'RUST', 'CPP', 'delta', 'winner')

$rustAll = @(); $cppAll = @(); $rustWins = 0; $cppWins = 0; $ties = 0

foreach ($r in 1..$Rounds) {
    # Alternate which backend runs first.
    if ($r % 2 -eq 1) {
        $rust = Invoke-Backend 'rust'; $cpp = Invoke-Backend 'cpp'
    } else {
        $cpp = Invoke-Backend 'cpp';  $rust = Invoke-Backend 'rust'
    }

    $delta = ($rust - $cpp) / $cpp * 100.0
    $winner = if ([math]::Abs($delta) -lt 0.10) { $ties++; 'tie' }
              elseif ($delta -gt 0) { $rustWins++; 'RUST' }
              else { $cppWins++; 'CPP' }

    $rustAll += $rust; $cppAll += $cpp
    Write-Host ('{0,-6} {1,9:N2} {2,9:N2} {3,8:+0.00;-0.00}%  {4}' -f $r, $rust, $cpp, $delta, $winner)
}

$rustAvg = ($rustAll | Measure-Object -Average).Average
$cppAvg  = ($cppAll  | Measure-Object -Average).Average
$avgDelta = ($rustAvg - $cppAvg) / $cppAvg * 100.0

Write-Host ('{0,-6} {1,9:N2} {2,9:N2} {3,8:+0.00;-0.00}%  {4}' -f 'avg', $rustAvg, $cppAvg, $avgDelta, "$rustWins W / $cppWins L / $ties T")
Write-Host ''

$decided = $rustWins + $cppWins
if ($decided -gt 0) {
    # Two-sided sign test: P(>= max(w,l) wins | fair coin).
    $k = [math]::Max($rustWins, $cppWins)
    $sum = 0.0
    foreach ($i in $k..$decided) {
        $c = 1.0
        for ($j = 0; $j -lt $i; $j++) { $c = $c * ($decided - $j) / ($j + 1) }
        $sum += $c
    }
    $p = 2.0 * $sum / [math]::Pow(2, $decided)
    Write-Host ('sign test over {0} decided rounds: p = {1:N4}' -f $decided, [math]::Min($p, 1.0))
}

if ([math]::Abs($avgDelta) -lt 1.0) {
    Write-Host "VERDICT: parity (|delta| < 1%, inside BENCHMARKS.md's stated uncertainty)" -ForegroundColor Green
} elseif ($avgDelta -gt 0) {
    Write-Host ('VERDICT: Rust ahead by {0:N2}%' -f $avgDelta) -ForegroundColor Green
} else {
    Write-Host ('VERDICT: Rust behind by {0:N2}% -- optimize loop required' -f [math]::Abs($avgDelta)) -ForegroundColor Yellow
}
