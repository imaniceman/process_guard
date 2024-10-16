@echo off
sc stop DWMMonitorService
if %errorlevel% neq 0 (
    echo Failed to stop DWMMonitorService
    exit /b %errorlevel%
)
echo DWMMonitorService stopped successfully