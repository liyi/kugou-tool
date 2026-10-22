@echo off
setlocal EnableExtensions
chcp 65001 >nul
pushd "%~dp0"

set "CC64="
set "CC32="
set "RC64="
set "RC32="
set "OK=0"

for /f "delims=" %%G in ('where gcc 2^>nul') do call :check_cc "%%G"
call :check_cc "C:\msys64\mingw64\bin\gcc.exe"
call :check_cc "C:\msys64\ucrt64\bin\gcc.exe"
call :check_cc "C:\msys64\mingw32\bin\gcc.exe"
call :check_cc "C:\mingw64\bin\gcc.exe"
call :check_cc "C:\mingw32\bin\gcc.exe"
call :check_cc "C:\MinGW\bin\gcc.exe"
call :check_cc "C:\ProgramData\mingw64\mingw64\bin\gcc.exe"

if not defined CC64 echo [SKIP] x64 compiler not found.
if not defined CC32 echo [SKIP] x86 compiler not found.

if defined CC64 call :build x64
if defined CC32 call :build x86

if "%OK%"=="0" (
    echo [ERROR] No usable MinGW-w64 compiler found.
    popd
    endlocal
    if /i not "%~1"=="nopause" pause
    exit /b 1
)

echo.
echo Build finished. Output: bin\x64\kugou-tool.exe and/or bin\x86\kugou-tool.exe
popd
endlocal
if /i not "%~1"=="nopause" pause
exit /b 0

:check_cc
set "CAND=%~1"
if not exist "%CAND%" goto :eof
if defined CC64 if defined CC32 goto :eof
set "CANDDIR="
for %%I in ("%CAND%") do if exist "%%~dpIwindres.exe" set "CANDDIR=%%~dpI"
if not defined CANDDIR goto :eof
set "MACH="
"%CAND%" -dumpmachine > "%TEMP%\kugou_tool_machine.txt" 2>nul
if not exist "%TEMP%\kugou_tool_machine.txt" goto :eof
set /p MACH=<"%TEMP%\kugou_tool_machine.txt"
del "%TEMP%\kugou_tool_machine.txt" >nul 2>&1
if not defined MACH goto :eof
echo %MACH% | findstr /i "x86_64" >nul
if not errorlevel 1 (
    if not defined CC64 (
        set "CC64=%CAND%"
        set "RC64=%CANDDIR%windres.exe"
    )
    goto :eof
)
echo %MACH% | findstr /i "i686 i386" >nul
if not errorlevel 1 (
    if not defined CC32 (
        set "CC32=%CAND%"
        set "RC32=%CANDDIR%windres.exe"
    )
)
goto :eof

:build
set "ARCH=%~1"
if /i "%ARCH%"=="x64" (
    set "CC=%CC64%"
    set "RC=%RC64%"
) else (
    set "CC=%CC32%"
    set "RC=%RC32%"
)
if not exist "bin\%ARCH%" mkdir "bin\%ARCH%"
if not exist "build\%ARCH%" mkdir "build\%ARCH%"
for %%I in ("%CC%") do set "CCDIR=%%~dpI"
set "PATH=%CCDIR%;%PATH%"
echo [BUILD] %ARCH% ...
pushd src
"%RC%" -I. -O coff -o "..\build\%ARCH%\app_res.o" app.rc
if errorlevel 1 (
    popd
    echo [ERROR] %ARCH%: resource compilation failed.
    goto :eof
)
popd
"%CC%" -std=c11 -O2 -Wall -Wextra -municode -mwindows -DUNICODE -D_UNICODE -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -Isrc src\main.c src\gui.c src\cli.c src\convert.c src\app.c src\util.c src\crypto.c src\inflate.c src\krc.c src\keydb.c src\audio.c "build\%ARCH%\app_res.o" -o "bin\%ARCH%\kugou-tool.exe" -static -static-libgcc -s -lcomctl32 -lcomdlg32 -lshell32 -lole32 -loleaut32 -luuid -lshlwapi -lgdi32 -luser32 -lkernel32 -ladvapi32
if errorlevel 1 (
    echo [ERROR] %ARCH%: compile/link failed.
    goto :eof
)
echo [OK] bin\%ARCH%\kugou-tool.exe
set "OK=1"
goto :eof
