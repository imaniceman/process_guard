@echo off
:: Check for administrative privileges
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo This script requires administrative privileges.
    echo Please run this script as an administrator.
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0%~nx0\"\"' -Verb RunAs"
    exit /b 1
)

sc start ProcessMonitorService
if %errorlevel% neq 0 (
    echo Failed to start ProcessMonitorService
    exit /b %errorlevel%
)
echo ProcessMonitorService started successfully