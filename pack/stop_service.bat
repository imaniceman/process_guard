@echo off

:: Check for administrative privileges
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo This script requires administrative privileges.
    echo Please run this script as an administrator.
    powershell -Command "Start-Process cmd -ArgumentList '/c %~dp0%~nx0' -Verb RunAs"
    exit /b 1
)


sc stop DWMMonitorService
if %errorlevel% neq 0 (
    echo Failed to stop DWMMonitorService
    exit /b %errorlevel%
)
echo DWMMonitorService stopped successfully