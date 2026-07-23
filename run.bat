@echo off
setlocal
echo ====================================================
echo   NGAP / NAS Wireshark Diagnostic Analyzer
echo   Cross-Platform Windows Launcher
echo ====================================================
echo.

if "%~1"=="" (
    echo Launching Web GUI Dashboard on http://localhost:8080 ...
    python main.py --gui
) else (
    echo Analyzing capture file: %~1
    python main.py -f %*
)
