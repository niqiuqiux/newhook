@echo off
setlocal

set NEWHOOK_DIR=%~dp0
set BUILD_DIR=%NEWHOOK_DIR%build
set REMOTE_DIR=/data/local/tmp

echo ============================================
echo   newhook - build, push, and run test
echo ============================================
echo.

:: ── Step 1: CMake configure ──
echo [1/4] CMake configure ...
C:\mingw64\bin\cmake.EXE ^
    -DCMAKE_BUILD_TYPE:STRING=Debug ^
    -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE ^
    --no-warn-unused-cli ^
    -S "%NEWHOOK_DIR%." ^
    -B "%BUILD_DIR%" ^
    -G "MinGW Makefiles"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configure failed!
    exit /b 1
)

:: ── Step 2: Build ──
echo.
echo [2/4] Building ...
C:\mingw64\bin\cmake.EXE --build "%BUILD_DIR%" --parallel
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed!
    exit /b 1
)

echo.
echo   Output files:
dir /b "%BUILD_DIR%\libnewhook.a" "%BUILD_DIR%\libnewhook.so" "%BUILD_DIR%\newhook_test*" 2>nul
echo.

:: ── Step 3: Push to device ──
echo [3/4] Pushing to device (%REMOTE_DIR%) ...
adb push "%BUILD_DIR%\newhook_test" %REMOTE_DIR%/newhook_test
if %ERRORLEVEL% neq 0 (
    echo [ERROR] adb push failed! Is device connected?
    exit /b 1
)
adb shell chmod 755 %REMOTE_DIR%/newhook_test

:: ── Step 4: Run on device ──
echo.
echo [4/4] Running test on device ...
echo ============================================
adb shell %REMOTE_DIR%/newhook_test
set RESULT=%ERRORLEVEL%
echo ============================================
echo.

if %RESULT% equ 0 (
    echo   ALL TESTS PASSED
) else (
    echo   SOME TESTS FAILED (exit code: %RESULT%)
)

endlocal
exit /b %RESULT%
