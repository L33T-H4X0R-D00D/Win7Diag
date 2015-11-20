@ECHO OFF
SETLOCAL

set version=Version 22.
set updated=Last updated 11/20/2015.
set compatibility=Compatible with Windows 7 and Windows 2008 R2.
set incompatibility=Incompatible with Windows Vista.
rem Log file is generated in the same directory as the script.
PUSHD "%~dp0"
cls
color 0a
echo Compatibility test.
rem Test for administrator elevation. "NET SESSION" requires administrative rights to access. The results of the command are sent to null so they will not display. 
NET SESSION > nul 2>&1
rem If statement to confirm if the previous command completed successfully (prompt has admin rights) or unsuccessfully (prompt does not have admin rights).
IF %ERRORLEVEL% EQU 0 (
rem Short pause to allow user to read prompts.
    timeout /t 1 /nobreak > nul
    echo Administrator privileges: Detected
    ) ELSE (
    cls
    color 0c
    echo This tool must be run from an administrator elevated command prompt. 
    echo Right click the script and choose "Run as administrator". 
    goto :endbroke
)
rem Test for 64 bit command prompt. "%processor_architecture%" is a global variable that identifies whether a system is x86 (32bit) or AMD64 (64bit). 
IF %processor_architecture% EQU AMD64 (
rem Short pause to allow user to read prompts.
    timeout /t 1 /nobreak > nul
    echo 64 bit command prompt: Detected
    ) else (
    cls
    color 0c
    echo This tool must be run from a 64 bit command prompt. Please run cmd.exe in 
    echo C:Windows\System32 not C:\Windows\SysWOW64.
    goto :endbroke
)
rem Short pause to allow user to read prompts.
timeout /t 1 /nobreak > nul
echo System compatible: Yes
rem Short pause to allow user to read prompts.
timeout /t 1 /nobreak > nul

rem Menu display.
:menu
cls
color 0e
echo %version%  %updated%
echo %compatibility%
echo %incompatibility%
echo Please close all other applications before continuing.
echo.
echo.
echo 1  Basic desktop diag - 1-5 minutes
echo 2  Enhanced desktop diag - 10-30 minutes reboot required.
Echo 3  Enhanced desktop diag - W/log import reboot required. 200+MB file size.
echo 4  Server diag - 10-30 Minutes. Reboot required.
echo 5  Force group policy update - 5 minutes. Reboot required.
echo 6  Force checkdisk to run on next boot - Instant.
echo 7  Install Telnet client - 1-5 minutes.
echo 8  IIS reset - Instant.
echo 9  Reset WMI performance counters - Instant.
echo 10 Display prefetch options - Instant.
echo 11 Windows update repair - 1-5 minutes.
echo 12 Fix "No licenses available" RDP error - 1 minute.
echo 13 Disable hibernation file - Instant.
echo 14 Check if TRIM is enabled - Instant.
echo 15 Open godmode settings - Instant.
echo 16 Fix hidden devices in device manager - Instant.
echo 17 Reset NTP source to pool.ntp.org - Instant.
echo E  EXIT.
echo.

rem Menu input commands.  These lead to anchors in the display section which then makes calls to the functions.
SET /P M=Type 1 - 17 or E then press ENTER:
IF %M%==1 GOTO :basicworkstation
IF %M%==2 GOTO :enhancedworkstation
IF %M%==3 GOTO :enhancedworkstationimportlogs
IF %M%==4 GOTO :server
IF %M%==5 GOTO :gpo
IF %M%==6 GOTO :cdirty
IF %M%==7 GOTO :telnet
IF %M%==8 GOTO :iisreset
IF %M%==9 GOTO :wmi
IF %M%==10 GOTO :prefetch
IF %M%==11 GOTO :wuafix
IF %M%==12 GOTO :rdpfix
IF %M%==13 GOTO :hiboff
IF %M%==14 GOTO :trimcheck
IF %M%==15 GOTO :godmode
IF %M%==16 GOTO :devicemanager
IF %M%==17 GOTO :timefix
IF %M%==E GOTO :end
IF %M%==e GOTO :end
IF %M%==starwars GOTO :starwars

rem Display section. This section controls what is shown on the screen and calls to the functions which do the described work.
:basicworkstation
call:fstart
echo Basic Workstation. >> results.txt
echo. >> results.txt
echo. >> results.txt
echo Basic Workstation
echo Diagnostic 1 of 5.
echo System Information.
echo Û....
call:finfo
echo Basic Workstation
echo Diagnostic 2 of 5.
echo Network Time.
echo ÛÛ...
call:fnettime
echo Basic Workstation
echo Diagnostic 3 of 5.
echo Winsock.
echo ÛÛÛ..
call:fnetreset
echo Basic Workstation
echo Diagnostic 4 of 5.
echo IP Address.
echo ÛÛÛÛ.
call:fipconfigdhcp
echo Basic Workstation
echo Diagnostic 5 of 5.
echo Group Policy.
echo ÛÛÛÛÛ
call:fgpolist
call:fwmi
call:fend
goto :endworkednoreboot

:enhancedworkstation
call:fstart
echo Enhanced Workstation. >> results.txt
echo. >> results.txt
echo. >> results.txt
echo Enhanced Workstation
echo Diagnostic 1 of 9.
echo System Information.
echo л........
call:finfo
echo Enhanced Workstation
echo Diagnostic 2 of 9.
echo System Information.
echo лл.......
call:fnettime
echo Enhanced Workstation
echo Diagnostic 3 of 9.
echo System Information.
echo ллл......
call:fnetreset
echo Enhanced Workstation
echo Diagnostic 4 of 9.
echo System Information.
echo лллл.....
call:fipconfigdhcp
echo Enhanced Workstation
echo Diagnostic 5 of 9.
echo System Information.
echo ллллл....
call:fgpolist
echo Enhanced Workstation
echo Diagnostic 6 of 9.
echo System Information.
echo лллллл...
call:fsfc
echo Enhanced Workstation
echo Diagnostic 7 of 9.
echo System Information.
echo ллллллл..
call:fchkdsk
echo Enhanced Workstation
echo Diagnostic 8 of 9.
echo System Information.
echo лллллллл.
call:fdefrag
echo Enhanced Workstation
echo Diagnostic 9 of 9.
echo System Information.
echo ллллллллл
rem call:fwinsat
call:fwmi
call:fend
goto :endworkedreboot

:enhancedworkstationimportlogs
call:fstart
echo Enhanced Workstation. >> results.txt
echo. >> results.txt
echo. >> results.txt
echo Enhanced Workstation
echo Diagnostic 1 of 9.
echo System Information.
echo л........
call:finfo
echo Enhanced Workstation
echo Diagnostic 2 of 9.
echo System Information.
echo лл.......
call:fnettime
echo Enhanced Workstation
echo Diagnostic 3 of 9.
echo System Information.
echo ллл......
call:fnetresetimportlogs
echo Enhanced Workstation
echo Diagnostic 4 of 9.
echo System Information.
echo лллл.....
call:fipconfigdhcp
echo Enhanced Workstation
echo Diagnostic 5 of 9.
echo System Information.
echo ллллл....
call:fgpolist
echo Enhanced Workstation
echo Diagnostic 6 of 9.
echo System Information.
echo лллллл...
call:fsfcimportlogs
echo Enhanced Workstation
echo Diagnostic 7 of 9.
echo System Information.
echo ллллллл..
call:fchkdsk
echo Enhanced Workstation
echo Diagnostic 8 of 9.
echo System Information.
echo лллллллл.
call:fdefrag
echo Enhanced Workstation
echo Diagnostic 9 of 9.
echo System Information.
echo ллллллллл
rem call:fwinsat
call:fwmi
call:fend
goto :endworkedreboot

:server
call:fstart
echo Server. >> results.txt 
echo. >> results.txt
echo. >> results.txt
echo Server.
echo Diagnostic 1 of 10.
echo System Information.
echo л.........
call:finfo
echo Server.
echo Diagnostic 2 of 10.
echo System Information.
echo лл........
call:fnettime
echo Server.
echo Diagnostic 3 of 10.
echo System Information.
echo ллл.......
call:fnetreset
echo Server.
echo Diagnostic 4 of 10.
echo System Information.
echo лллл......
call:fipconfigstatic
echo Server.
echo Diagnostic 5 of 10.
echo System Information.
echo ллллл.....
call:fgpolist
echo Server.
echo Diagnostic 6 of 10.
echo System Information.
echo лллллл....
call:fsfc
echo Server.
echo Diagnostic 7 of 10.
echo System Information.
echo ллллллл...
call:fchkdsk
echo Server.
echo Diagnostic 8 of 10.
echo System Information.
echo лллллллл..
call:fdefrag
echo Server.
echo Diagnostic 9 of 10.
echo System Information.
echo ллллллллл.
call:fwinsat
echo Server.
echo Diagnostic 10 of 10.
echo System Information.
echo ллллллллл
call:ffsmo
call:fend
goto :endworkedreboot

:gpo
call:fgpoupdate
goto :end

:cdirty
call:fcdirty
echo Scandisk will run on reboot.
timeout /t 3 /nobreak > nul
goto :menu

:telnet
call:ftelnet
echo Telnet installed.
timeout /t 3 /nobreak > nul
goto :menu

:iisreset
call:fiisreset
echo IIS reset.
timeout /t 3 /nobreak > nul
goto :menu

:wmi
call:fwmi
echo WMI couters reset successfully.
timeout /t 3 /nobreak > nul
goto :menu

:prefetch
cls
echo 0x0 = Disabled
echo 0x1 = Application launch prefetching enabled
echo 0x2 = Boot prefetching enabled
echo 0x3 = Application launch and boot enabled
echo.
echo Current Prefetch Settings:
call:fprefetch

:wuafix
cls
echo This will stop Windows Update related services, remove several cache files and 
echo re-register Windows Update related DLLs in the registry. A reboot is recommended 
echo before attempting to re-run Windows Update after fix.
echo.
pause
call:fwuafix
goto :menu

:rdpfix
cls
echo This will fix the following RDP error.
echo.
echo The remote session was disconnected because there are no Terminal Server client
echo access licenses available for this computer. 
echo. 
echo Registry entries are exported to C:\ before being deleted. The Terminal services
echo client will open after the fix has been applied.  You must use it to connect to 
echo a remote computer to complete the fix.
echo.
echo.
pause
call:frdpfix
goto :menu

:hiboff
cls
call:fhiboff
echo Hibernation file disabled. 
timeout /t 3 /nobreak > NUL
goto :menu

:trimcheck
cls
echo Trim is a feature that prevents SSD performance degredation over time 
echo due to the way that SSDs write and erase data.  If you have an SSD 
echo trim should be enabled. 
echo. 
call:ftrimcheck
goto :menu

:godmode
call:fgodmode
goto :menu

:devicemanager
echo This will temporarily change an environment variable forcing 
echo Device Manager to show installed but disconnected devices.
echo This is necessary after P2V'ing a windows machine so that 
echo you can remove the one or more disconnected network cards
echo from the new VM. 
echo.
echo After this prompt Device manager will open. 
echo You must click "View" then "Show hidden devices". 
echo You may remove any network cards which are grayed out.
pause
call:fdevicemanager
goto :menu

:timefix
echo This will reset your NTP source to Pool.NTP.Org.
call:ftimefix
goto :menu

:starwars
call:fstarwars
goto :menu

rem Completion Messages
:endbroke
echo No diagnostics were performed.
pause
color 07
goto :end

:endworkednoreboot
cls
color 0e
echo Diagnostic complete. Please email the contents of 
echo the log file to your IT administrator with a short 
echo description of the issue you were experiencing. 
pause
color 07
cls
results.txt
goto :end

:endworkedreboot
cls
color 0e
echo Diagnostic complete. Please email the contents of 
echo the log file to your IT administrator with a short 
echo description of the issue you were experiencing.
pause
cls
results.txt
echo Your computer will now reboot.
pause
color 07
shutdown -r 
goto :end

rem Function section.
:fstart
del results.txt
color 0c
cls
echo. >> results.txt
echo. >> results.txt
echo Script version number.  Echo % version % >> results.txt
echo %version% >> results.txt
echo. >> results.txt
echo Script last updated. Echo % updated % >> results.txt
echo %updated% >> results.txt
echo. >> results.txt
echo Start Time. Time /t >> results.txt
time /t >> results.txt
goto:eof

:finfo
echo Current System Timezone. TzUtil /g >> results.txt
tzutil /g >> results.txt
echo. >> results.txt
echo. >> results.txt
echo Current Machine Hostname. Hostname >> results.txt
hostname >> results.txt
echo. >> results.txt
echo Current User Logged on. Whoami >> results.txt
whoami >> results.txt
echo. >> results.txt
echo Command Prompt Bit Level. Echo %PROCESSOR _ ARCHITECTURE% >> results.txt
echo %PROCESSOR_ARCHITECTURE% >> results.txt
echo. >> results.txt
echo OS Bit Level. Wmic os get osarchitecture>> results.txt
wmic os get osarchitecture >> results.txt
echo. >> results.txt
echo. >> results.txt
echo System Info. Systeminfo >> results.txt
systeminfo >> results.txt
echo. >> results.txt
echo Currently Running Process List. Tasklist /v /fo >> results.txt
tasklist /v /fo list >> results.txt
echo. >> results.txt
echo Windows Licensing. Cscript c:\Windows\System32\slmgr.vbs /dlv >> results.txt
cscript c:\Windows\System32\slmgr.vbs /dlv >> results.txt
echo. >> results.txt
echo System Path. Echo path >> results.txt
path >> results.txt
echo. >> results.txt
echo Statistics and Uptime. Net statistics workstation >> results.txt
net statistics workstation >> results.txt
echo. >> results.txt
echo List available shares. Net share >> results.txt
net share >> results.txt
echo. >> results.txt
echo List partition offset. Wmic partition get Blocksize, StartingOffset, Name, Index >> results.txt
Wmic partition get Blocksize, StartingOffset, Name, Index >> results.txt
echo. >> results.txt
cls
goto:eof

:fnettime
echo Network Time. W32tm /query /status>> results.txt
w32tm /query /status >> results.txt
echo. >> results.txt
echo. >> results.txt
echo Network Time. W32tm /query /configuration >> results.txt
w32tm /query /configuration >> results.txt
echo. >> results.txt
echo Network Time. W32tm /resync >> results.txt
w32tm /resync >> results.txt
echo. >> results.txt
cls
goto:eof

:fnetreset
echo TCP/IP Reset. Netsh int ip reset C:\netsh.log.txt  >> results.txt
netsh int ip reset C:\netsh.log.txt >> results.txt
echo. >> results.txt
echo Winsock Reset. Netsh winsock reset >> results.txt
netsh winsock reset >> results.txt
echo. >> results.txt
echo Branch Cache reset. Netsh branchcache reset >> results.txt
netsh branchcache reset  >> results.txt
cls
goto:eof

:fnetresetimportlogs
echo TCP/IP Reset. Netsh int ip reset C:\netsh.log.txt  >> results.txt
netsh int ip reset C:\netsh.log.txt >> results.txt
echo. >> results.txt
echo Copy Net Shell Log. Copy C:\netsh.log.txt C:\netsh.log-1.txt  >> results.txt
Copy C:\netsh.log.txt C:\netsh.log-1.txt >> results.txt
echo. >> results.txt
echo Copy Net Shell Log Into Results.txt. Type C:\netsh.log-1.txt >> results.txt
type C:\netsh.log-1.txt >> results.txt
echo. >> results.txt
echo Delete The Copied Log File. Del C:\netsh.log-1.txt >> results.txt
del C:\netsh.log-1.txt >> results.txt
echo Winsock Reset. Netsh winsock reset >> results.txt
netsh winsock reset >> results.txt
echo. >> results.txt
echo Branch Cache reset. Netsh branchcache reset >> results.txt
netsh branchcache reset  >> results.txt
cls
goto:eof

:fipconfigdhcp
echo IP Diags. Ipconfig /all >> results.txt
ipconfig /all >> results.txt
echo. >> results.txt
echo IP Diags. Ipconfig /displaydns >> results.txt
ipconfig /displaydns >> results.txt
echo. >> results.txt
echo IP Diags. Ipconfig /flushdns >> results.txt
ipconfig /flushdns >> results.txt
echo. >> results.txt
echo IP Diags. Ipconfig /release >> results.txt
ipconfig /release >> results.txt
echo. >> results.txt
echo IP Diags. Ipconfig /renew >> results.txt
ipconfig /renew >> results.txt
echo. >> results.txt
echo Netbios Name Resolution. Nbtstat -n >> results.txt
nbtstat -n >> results.txt
echo. >> results.txt
echo Active TCP Connections Resolved. Netstat >> results.txt
netstat >> results.txt
echo. >> results.txt
echo Active TCP Connections Unresolved. Netstat /n >> results.txt
netstat /n >> results.txt
echo. >> results.txt
echo Static Routes. Route print >> results.txt
route print >> results.txt
echo. >> results.txt
cls
goto:eof

:fipconfigstatic
echo IP Address. Ipconfig /all >>results.txt
ipconfig /all >> results.txt
echo. >> results.txt
echo IP Address. Ipconfig /displaydns >> results.txt
ipconfig /displaydns >> results.txt
echo. >> results.txt
echo IP Address. Ipconfig /flushdns >> results.txt
ipconfig /flushdns >> results.txt
echo. >> results.txt
echo Netbios Name Resolution. Nbtstat -n >> results.txt
nbtstat -n >> results.txt
echo. >> results.txt
echo Active TCP Connections Resolved. Netstat >> results.txt
netstat >> results.txt
echo. >> results.txt
echo Active TCP Connections Not Resolved. Netstat /n >> results.txt
netstat /n >> results.txt
echo. >> results.txt
echo Static Routes. Route print >> results.txt
route print >> results.txt
echo. >> results.txt
cls
goto:eof

:fgpolist
echo Computer Group Policy. Gpresult /v /scope COMPUTER >> results.txt
gpresult /v /scope COMPUTER >> results.txt
echo. >> results.txt
echo User Group Policy. Gpresult /v /scope USER >> results.txt
Gpresult /v /scope USER >> results.txt
echo. >> results.txt
cls
goto:eof

:fsfc
echo System File Check. Sfc.exe /scannow >> results.txt
sfc /scannow >> results.txt
echo. >> results.txt
cls
goto:eof

:fsfcimportlogs
echo System File Check. Sfc.exe /scannow >> results.txt
sfc /scannow >> results.txt
echo. >> results.txt
echo Copy System File Check Log. Copy C:\Windows\Logs\CBS\CBS.log C:\Windows\Logs\CBS\CBS-1.log  >> results.txt
copy C:\Windows\Logs\CBS\CBS.log C:\Windows\Logs\CBS\CBS-1.log >> results.txt
echo. >> results.txt
echo Copy System File Check Log Into Results.txt. Type C:\Windows\Logs\CBS\CBS-1.log >> results.txt
type C:\Windows\Logs\CBS\CBS-1.log >> results.txt
echo. >> results.txt
echo Delete The Copied Log File. Del C:\Windows\Logs\CBS\CBS-1.log >> results.txt
del C:\Windows\Logs\CBS\CBS-1.log >> results.txt
echo. >> results.txt
cls
goto:eof

:fchkdsk
rem This runs a read only check disk and dumps the results into the log file.  If errors are found the partition should be marked dirty so check disk can repair the errors on next reboot.
echo Disk Check. Chkdsk.exe >> results.txt
chkdsk >> results.txt
echo. >> results.txt
cls
goto:eof

:fdefrag
echo Defrag. Defrag.exe /C /H /U /X >> results.txt
defrag /C /H /U /X >> results.txt
echo. >> results.txt
cls
goto:eof

:fwinsat
echo Winsat. Winsat.exe Cpuformal >> results.txt
winsat cpuformal >> results.txt
echo. >> results.txt
echo Winsat. Winsat.exe Memformal >> results.txt
winsat memformal  >> results.txt
echo.  >> results.txt
echo Winsat. Winsat.exe Diskformal >> results.txt
winsat diskformal  >> results.txt
echo.  >> results.txt
goto:eof

:ffsmo
echo Query FSMO Roles. Netdom /query fsmo >> results.txt
netdom /query fsmo >> results.txt
echo. >> results.txt
echo Query Domain Controllers. Netdom /query DC >> results.txt
netdom /query DC >> results.txt
echo. >> results.txt
echo Query Windows System Logs For Errors. Wevtutil qe System "/q:*[System[(Level=1 or Level=2)]]" /f:text /RD:TRUE /C:10 >> results.txt
wevtutil qe System "/q:*[System[(Level=1 or Level=2)]]" /f:text /RD:TRUE /C:10
echo. >> results.txt
echo Domain Controller Diagnostics. Dcdiag >> results.txt
dcdiag >> results.txt
echo. >> results.txt
echo File System Utility. Fsutil fsinfo ntfsinfo C: >> results.txt
fsutil fsinfo ntfsinfo c: >> results.txt
echo. >> results.txt
echo Currently Running Services. Net start >> results.txt
net start >> results.txt
echo. >> results.txt
echo Completion Time. >> results.txt
time /t >> results.txt
goto:eof

:fgpoupdate
cls
rem This kicks off a reboot in 5 minutes and runs a group policy update. The GPO update command will log the user off if policies are applied that must be modified before login.
rem Since most users are unable to look at logged off machine and wait 5 minutes before logging in, a reboot is scheduled for 5 minutes.
rem You may run this option and tell the user they may begin using their computer again after it has restarted.
shutdown -r -t 300 | gpupdate /force /logoff
goto:eof

:fcdirty
cls
rem This marks the C partition as dirty so a check disk will be run at next boot.
fsutil dirty set c:
goto:eof

:ftelnet
cls
echo Installing Telnet Client
rem This will install the Microsoft Telnet client via the Microsoft Package Manager.  This is essential if you wish to use the starwars option.
pkgmgr /iu:"TelnetClient"
timeout /t 10 /nobreak > NUL
goto:eof

:fiisreset
cls
rem This will restart IIS, if installed. 
iisreset >> results.txt
goto:eof

:fwmi
cls
rem These commands log the current registry settings for performance counters, then rebuilds the counters.
echo Query performance counters. Lodctr /q >> results.txt
lodctr /Q >> results.txt
echo. >> results.txt
echo Rebuild performance counters. Lodctr /r >> results.txt
lodctr /r >> results.txt
echo. >> results.txt
echo. >> results.txt
echo Query performance counters. Lodctr /q >> results.txt
lodctr /Q >> results.txt
goto:eof

:fprefetch
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher
echo.
echo.

SET /P M=Type 0,1, 2, 3, or E then press ENTER:
IF %M%==0 GOTO 
IF %M%==1 GOTO 
IF %M%==2 GOTO 
IF %M%==3 GOTO 
IF %M%==e GOTO :menu
IF %M%==E GOTO :menu
goto:eof

:fwuafix
rem Taken from MS KB971058.
net stop bits >> results.txt
net stop wuauserv >> results.txt
net stop appidsvc >> results.txt
net stop cryptsvc >> results.txt
del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" >> results.txt
ren %systemroot%\SoftwareDistribution SoftwareDistribution.bak >> results.txt
ren %systemroot%\system32\catroot2 catroot2.bak >> results.txt
sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU) >> results.txt
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU) >> results.txt
regsvr32.exe atl.dll >> results.txt
regsvr32.exe urlmon.dll >> results.txt
regsvr32.exe mshtml.dll >> results.txt
regsvr32.exe shdocvw.dll >> results.txt
regsvr32.exe browseui.dll >> results.txt
regsvr32.exe jscript.dll >> results.txt
regsvr32.exe vbscript.dll >> results.txt
regsvr32.exe scrrun.dll >> results.txt
regsvr32.exe msxml.dll >> results.txt
regsvr32.exe msxml3.dll >> results.txt
regsvr32.exe msxml6.dll >> results.txt
regsvr32.exe actxprxy.dll >> results.txt
regsvr32.exe softpub.dll >> results.txt
regsvr32.exe wintrust.dll >> results.txt
regsvr32.exe dssenh.dll >> results.txt
regsvr32.exe rsaenh.dll >> results.txt
regsvr32.exe gpkcsp.dll >> results.txt
regsvr32.exe sccbase.dll >> results.txt
regsvr32.exe slbcsp.dll >> results.txt
regsvr32.exe cryptdlg.dll >> results.txt
regsvr32.exe oleaut32.dll >> results.txt
regsvr32.exe ole32.dll >> results.txt
regsvr32.exe shell32.dll >> results.txt
regsvr32.exe initpki.dll >> results.txt
regsvr32.exe wuapi.dll >> results.txt
regsvr32.exe wuaueng.dll >> results.txt
regsvr32.exe wuaueng1.dll >> results.txt
regsvr32.exe wucltui.dll >> results.txt
regsvr32.exe wups.dll >> results.txt
regsvr32.exe wups2.dll >> results.txt
regsvr32.exe wuweb.dll >> results.txt
regsvr32.exe qmgr.dll >> results.txt
regsvr32.exe qmgrprxy.dll >> results.txt
regsvr32.exe wucltux.dll >> results.txt
regsvr32.exe muweb.dll >> results.txt
regsvr32.exe wuwebv.dll >> results.txt
net start bits >> results.txt
net start wuauserv >> results.txt
net start appidsvc >> results.txt
net start cryptsvc >> results.txt
goto:eof

:frdpfix
rem Taken from https://technet.microsoft.com/en-us/library/cc756826%28v=ws.10%29.aspx#BKMK_12
reg.exe export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing" "C:\microsoftlicensing.reg"
reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing" /f
mstsc.exe
goto:eof

:fhiboff
rem If there is no need for a computer to hibernate the feature can be turned off.  The hibernation file is the same size as system memory.
rem This is especially useful for machines with large amounts of memory and small amounts of disk space.
powercfg.exe /hibernate off >> results.txt
goto:eof

:ftrimcheck
fsutil behavior query DisableDeleteNotify
echo.
echo If DisableDeleteNotify = 0, Trim is enabled.
pause
goto:eof

:fgodmode
mkdir "God Mode.{ED7BA470-8E54-465E-825C-99712043E01C}
mkdir "Location Settings.{00C6D95F-329C-409a-81D7-C46C66EA7F33}
mkdir "Biometric Settings.{0142e4d0-fb7a-11dc-ba4a-000ffe7ab428}
mkdir "Power Settings.{025A5937-A6BE-4686-A844-36FE4BEC8B6D}
mkdir "Icons And Notifications.{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}
mkdir "Credentials and Logins.{1206F5F1-0569-412C-8FEC-3204630DFB70}
mkdir "Programs and Features.{15eae92e-f17a-4431-9f28-805e482dafd4}
mkdir "Default Programs.{17cd9488-1228-4b2f-88ce-4298e93e0966}
mkdir "All NET Frameworks and COM Libraries.{1D2680C9-0E2A-469d-B787-065558BC7D43}
mkdir "All Networks For Current Connection.{1FA9085F-25A2-489B-85D4-86326EEDCD87}
mkdir "Network.{208D2C60-3AEA-1069-A2D7-08002B30309D}
mkdir "My Computer.{20D04FE0-3AEA-1069-A2D8-08002B30309D}
mkdir "Printers.{2227A280-3AEA-1069-A2DE-08002B30309D}
mkdir "Application Connections.{241D7C96-F8BF-4F85-B01F-E2B043341A4B}
mkdir "Firewall and Security.{4026492F-2F69-46B8-B9BF-5654FC07E423}
mkdir "Performance.{78F3955E-3B90-4184-BD14-5397C15F1EFC}
explorer "God Mode.{ED7BA470-8E54-465E-825C-99712043E01C}
goto:eof

:fdevicemanager
set devmgr_show_nonpresent_devices=1
start devmgmt.msc
goto:eof

:fstarwars
cls
color 07
telnet towel.blinkenlights.nl
goto:eof

:ftimefix
rem http://www.sysadminlab.net/windows/configuring-ntp-on-windows-2008-r2
w32tm /config /manualpeerlist:pool.ntp.org,0x8 /syncfromflags:MANUAL
net stop w32time
net start w32time
goto:eof

:fend
echo Completion Time. >> results.txt
time /t >> results.txt
goto:eof

:end
rem END OF TRANSMISSION.
