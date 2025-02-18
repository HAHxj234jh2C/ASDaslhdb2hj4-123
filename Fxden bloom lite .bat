@echo off

Title Fxden Bloom Lite
color a
chcp 65001 >nul 2>&1
cls



R Killing SystemSettings process
taskkill /F /FI "IMAGENAME eq SystemSettings.exe"
echo action complete
timeout 2 >nul
net stop wuauserv
net stop UsoSvc
echo action complete

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d 1 /f
echo action complete
timeout 2 >nul

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d 1 /f
echo action complete

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
echo action complete

timeout 3 >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
echo action complete

gpupdate /force
echo action complete

rd /s /q "C:\Windows\SoftwareDistribution"
md "C:\Windows\SoftwareDistribution"
echo action complete

timeout 1 >nul
net start wuauserv
net start UsoSvc
echo action complete
echo Bloom Lite applied successfully! Have fun!!!
pause

