@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Windows launcher for ssh-mux: check WSL and dependencies, map paths into
rem WSL, then run ssh-mux.py inside WSL. Keep this file ASCII only: non-UTF8
rem code pages break cmd parsing of multibyte text.
rem Installing WSL or packages is a system-level change; get user consent
rem first and follow the steps in SKILL.md.

where wsl.exe >nul 2>&1
if errorlevel 1 (
    echo ssh-mux: wsl.exe not found. Install WSL first ^(see SKILL.md; user consent required^).
    exit /b 1
)

wsl.exe -e true >nul 2>&1
if errorlevel 1 (
    echo ssh-mux: no installed WSL distro. Install one first ^(see SKILL.md; user consent required^).
    exit /b 1
)

wsl.exe -e bash -c "command -v python3 >/dev/null && command -v ssh >/dev/null" >nul 2>&1
if errorlevel 1 (
    echo ssh-mux: missing python3/ssh inside WSL. Install them first, e.g.:
    echo   wsl -u root -- apt-get install -y python3 openssh-client
    exit /b 1
)

wsl.exe -e python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" >nul 2>&1
if errorlevel 1 (
    echo ssh-mux: Python inside WSL is older than 3.7, please upgrade it first.
    exit /b 1
)

wsl.exe -e bash -c "command -v sshpass >/dev/null" >nul 2>&1
if errorlevel 1 (
    echo ssh-mux: note: sshpass not found in WSL, password login will fail. Install:
    echo   wsl -u root -- apt-get install -y sshpass
)

set "WSLPY="
if not exist "%~dp0ssh-mux.py" (
    echo ssh-mux: ssh-mux.py not found next to this script ^(%~dp0^)
    exit /b 1
)
for /f "usebackq delims=" %%p in (`wsl.exe -e wslpath -a "%~dp0ssh-mux.py" 2^>nul`) do set "WSLPY=%%p"
if not defined WSLPY (
    echo ssh-mux: cannot map %~dp0ssh-mux.py to a WSL path
    exit /b 1
)

rem Other subcommands preserve their original command line with %*.
rem Map push/pull local paths and exec --file, preserving inline commands.
set "EXECMODE=0"
if "%~1"=="exec" goto execmode
if "%~1"=="push" goto rebuild
if "%~1"=="pull" goto rebuild
:original
wsl.exe -e python3 "%WSLPY%" %*
exit /b %errorlevel%

rem Avoid CALL and parenthesized blocks while rebuilding arguments.
:execmode
set "EXECMODE=1"
:rebuild
set ARGS="%~1"
set "LOCALPOS=2"
if "%~1"=="pull" set "LOCALPOS=3"
set "POSITION=0"
set "ENDOPTS=0"
set "OPTVAL=0"
shift
:parse
rem Keep an explicitly empty argument distinct from the end of the list.
if [%1]==[] goto run
set "CUR=%~1"
if "%EXECMODE%"=="1" goto execarg
if "%OPTVAL%"=="1" goto optionvalue
if "%ENDOPTS%"=="1" goto positional
if "%CUR%"=="--" goto endoptions
if "%CUR%"=="--session" goto valuedoption
if "%CUR%"=="--timeout" goto valuedoption
if "%CUR%"=="--transport" goto valuedoption
if "%CUR%"=="--leg" goto valuedoption
if "%CUR:~0,1%"=="-" goto append
:positional
set /a POSITION+=1 >nul
if not "%POSITION%"=="%LOCALPOS%" goto append
if not defined CUR goto append
rem Resolve Windows relative paths before WSL sees their backslashes.
set "LOCAL=%~f1"
if "%LOCAL:~0,2%"=="\\" goto uncpath
if "%LOCAL:~0,2%"=="//" goto uncpath
rem Forward slashes also preserve drive roots when passed to wsl.exe.
set "LOCAL=%LOCAL:\=/%"
set "MAPPED="
for /f "usebackq delims=" %%w in (`wsl.exe -e wslpath -a "%LOCAL%" 2^>nul`) do set "MAPPED=%%w"
if not defined MAPPED goto badpath
set "CUR=%MAPPED%"
goto append
rem exec keeps inline commands unchanged using the original %* command line.
:execarg
if "%OPTVAL%"=="file" goto execfilevalue
if "%OPTVAL%"=="1" goto optionvalue
if "%ENDOPTS%"=="1" goto original
if "%CUR%"=="--" goto endoptions
if "%CUR%"=="--file" goto fileoption
if "%CUR%"=="-f" goto fileoption
if "%CUR:~0,7%"=="--file=" goto inlinefile
if "%CUR%"=="--session" goto valuedoption
if "%CUR%"=="--timeout" goto valuedoption
if "%CUR:~0,10%"=="--session=" goto append
if "%CUR:~0,10%"=="--timeout=" goto append
if "%CUR%"=="--help" goto original
if "%CUR%"=="-h" goto original
if "%POSITION%"=="1" goto original
set "POSITION=1"
goto append
:fileoption
set "OPTVAL=file"
goto append
:inlinefile
set ARGS=%ARGS% "--file"
set "CUR=%CUR:~7%"
:execfilevalue
set "OPTVAL=0"
if "%CUR%"=="-" goto append
if not defined CUR goto append
for %%f in ("%CUR%") do set "LOCAL=%%~ff"
if "%LOCAL:~0,2%"=="\\" goto uncpath
if "%LOCAL:~0,2%"=="//" goto uncpath
set "LOCAL=%LOCAL:\=/%"
set "MAPPED="
for /f "usebackq delims=" %%w in (`wsl.exe -e wslpath -a "%LOCAL%" 2^>nul`) do set "MAPPED=%%w"
if not defined MAPPED goto badpath
set "CUR=%MAPPED%"
goto append
:optionvalue
set "OPTVAL=0"
goto append
:endoptions
set "ENDOPTS=1"
goto append
:valuedoption
set "OPTVAL=1"
:append
rem Double trailing backslashes for Windows argv parsing, without changing
rem the value received by WSL (including remote paths and option values).
set "TAIL=%CUR%"
set "SLASHES="
:quotetail
if not "%TAIL:~-1%"=="\" goto quoted
set "SLASHES=%SLASHES%\"
set "TAIL=%TAIL:~0,-1%"
goto quotetail
:quoted
set ARGS=%ARGS% "%CUR%%SLASHES%"
shift
goto parse

:uncpath
echo ssh-mux: network paths are not supported; use a local drive path. >&2
exit /b 1
:badpath
echo ssh-mux: cannot map local path "%LOCAL%" to WSL. >&2
exit /b 1
:run
wsl.exe -e python3 "%WSLPY%" %ARGS%
exit /b %errorlevel%
