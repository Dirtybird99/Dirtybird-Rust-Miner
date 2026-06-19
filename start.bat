@echo off
REM Dirtybird Rust Miner -- launcher (Windows). Double-click to mine to the default pool.
REM To mine to YOUR wallet, edit the last line, e.g.:
REM     "%BIN%" -w dero1yourwalletaddress...
REM Other flags:  -d host:port   -t <threads>   --help
setlocal
cd /d "%~dp0"

set "BIN=dero-miner.exe"
if not exist "%BIN%" (
    echo error: dero-miner.exe not found. Run this from a release folder ^(next to dero-miner.exe^).
    pause
    exit /b 1
)

echo Starting miner (Ctrl-C to stop)...
echo.
"%BIN%" %*
