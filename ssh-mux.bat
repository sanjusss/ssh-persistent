@echo off
setlocal EnableExtensions

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

wsl.exe -e bash -c "command -v python3 >/dev/null && command -v ssh >/dev/null && command -v scp >/dev/null" >nul 2>&1
if errorlevel 1 (
    echo ssh-mux: missing python3/ssh/scp inside WSL. Install them first, e.g.:
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

rem Other subcommands pass their arguments through untouched with %*: a
rem rebuild loop would mangle arguments containing %% (double expansion).
rem Only push/pull need path mapping: their local file argument is written
rem as a drive-letter path. Mapping by shape (second char is ":") is safe
rem here because push/pull take no other drive-letter-looking values.
rem Case-sensitive on purpose: ssh-mux.py's argparse only accepts lowercase
rem push/pull, so accepting PUSH here would just fail later with invalid choice.
if "%~1"=="push" goto rebuild
if "%~1"=="pull" goto rebuild
wsl.exe -e python3 "%WSLPY%" %*
exit /b %errorlevel%

rem Rebuild loop for push/pull. Flow uses goto and no CALL: CALL re-parses
rem the rebuilt command line and expands %% sequences a second time. Flow
rem also avoids parenthesized blocks around set/if: inside a block, %VAR%
rem expands at parse time (before set runs).
:rebuild
set ARGS=
:parse
rem [%1] instead of "%~1": an explicitly passed empty argument ("") must not
rem be mistaken for the end of the argument list. %1 keeps its quotes, so it
rem only expands to nothing after the last argument was shifted away.
if [%1]==[] goto run
set "CUR=%~1"
if not defined CUR goto append
rem A trailing backslash would escape the closing quote when wsl.exe parses
rem its command line; it adds nothing for scp, so strip it first.
:strip
if "%CUR:~-1%"=="\" (set "CUR=%CUR:~0,-1%" & goto strip)
set "C2=%CUR:~1,1%"
if not "%C2%"==":" goto append
rem Compare against the stripped value: ORIG must match what wslpath was
rem given, otherwise a stripped trailing backslash would hide a failed mapping.
set "ORIG=%CUR%"
for /f "usebackq delims=" %%w in (`wsl.exe -e wslpath -a "%CUR%" 2^>nul`) do set "CUR=%%w"
if "%CUR%"=="%ORIG%" echo ssh-mux: warning: cannot map "%ORIG%" to a WSL path, passing it unchanged
:append
set ARGS=%ARGS% "%CUR%"
shift
goto parse

:run
wsl.exe -e python3 "%WSLPY%" %ARGS%
exit /b %errorlevel%
