@echo off
sc start DWMMonitorService
if %errorlevel% neq 0 (
    echo Failed to start DWMMonitorService
    exit /b %errorlevel%
)
echo DWMMonitorService started successfully