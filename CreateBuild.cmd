@REM This script requires MSBuild in PATH.

@REM Adjust values below before running this script.
@SETLOCAL
@SET BUILD_MAJOR_NO=1
@SET BUILD_MINOR_NO=1
@SET BUILD_REVISION_NO=0
@SET BUILD_PREFIX=C3
@SET BUILD_HEADER_FILE=Src\Common\C3_BUILD_VERSION_HASH_PART.hxx
@SET BUILDS_PATH=Builds

@REM Script part starts here.
@ECHO OFF

ECHO Cleaning from temporary files...
@CALL CleanTempFiles.cmd >nul 2>nul

ECHO Ensuring '%BUILDS_PATH%' folder exists...
IF EXIST "%BUILDS_PATH%" (RMDIR /s /q "%BUILDS_PATH%")
MKDIR %BUILDS_PATH%

SET BUILD_FULL_SIGNATURE=%BUILD_PREFIX%-%BUILD_MAJOR_NO%.%BUILD_MINOR_NO%.%BUILD_REVISION_NO%

ECHO Creating build folder - '%BUILD_FULL_SIGNATURE%'...
IF EXIST %BUILDS_PATH%\\%BUILD_FULL_SIGNATURE% (RMDIR /s /q "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%")
MKDIR %BUILDS_PATH%\\%BUILD_FULL_SIGNATURE% || GOTO :ERROR

ECHO Creating build versioning header...
SET BuildDefinition=#define C3_BUILD_VERSION
ECHO #include "StdAfx.h" > %BUILD_HEADER_FILE% || GOTO :ERROR
ECHO %BuildDefinition% "%BUILD_FULL_SIGNATURE%" >> %BUILD_HEADER_FILE% || GOTO :ERROR


if ""=="%~1" (
	set BuildTool=MSBuild
) else ( 
	set BuildTool=%1
)

ECHO.
ECHO Building x64 binaries...
%BuildTool% /nologo /verbosity:quiet /consoleloggerparameters:summary "Src" "/t:restore" "/t:GatewayConsoleExe;NodeRelayConsoleExe;NodeRelayDll;CebuLoader" "/p:Configuration=Release" "/p:Platform=x64" || GOTO :ERROR

ECHO.
ECHO Building x86 binaries...
%BuildTool% /nologo /verbosity:quiet /consoleloggerparameters:summary "Src" "/t:restore" "/t:GatewayConsoleExe;NodeRelayConsoleExe;NodeRelayDll;CebuLoader" "/p:Configuration=Release" "/p:Platform=x86" || GOTO :ERROR

ECHO.
ECHO Copying binaries...
IF NOT EXIST "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin" (MKDIR "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin") || GOTO :ERROR
COPY "Bin\\GatewayConsoleExe_r64.exe" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\GatewayConsoleExe_r64.exe" || GOTO :ERROR
COPY "Bin\\NodeRelayConsoleExe_r64.exe" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\NodeRelayConsoleExe_r64.exe" || GOTO :ERROR
COPY "Bin\\GatewayConsoleExe_r86.exe" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\GatewayConsoleExe_r86.exe" || GOTO :ERROR
COPY "Bin\\NodeRelayConsoleExe_r86.exe" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\NodeRelayConsoleExe_r86.exe" || GOTO :ERROR
COPY "Bin\\NodeRelayDll_r64.dll" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\NodeRelayDll_r64.dll" || GOTO :ERROR
COPY "Bin\\NodeRelayDll_r86.dll" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\NodeRelayDll_r86.dll" || GOTO :ERROR
COPY "Bin\\CebuLoader_r64.dll" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\CebuLoader_r64.dll" || GOTO :ERROR
COPY "Bin\\CebuLoader_r86.dll" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\CebuLoader_r86.dll" || GOTO :ERROR

ECHO.
ECHO Copying sample Gateway configuration...
COPY "Res\\GatewayConfiguration.json" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\Bin\\GatewayConfiguration.json" || GOTO :ERROR

ECHO.
ECHO Building WebController...
IF EXIST "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\WebController" (RMDIR /s /q "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\WebController") || GOTO :ERROR
dotnet publish -c Release "Src\\WebController\\Backend" || GOTO :ERROR
XCOPY /s /q "Bin\\WebController\\Release\\netcoreapp2.1\\publish" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\WebController\" || GOTO :ERROR

ECHO.
ECHO Copying scripts...
COPY "StartWebController.cmd" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\StartWebController.cmd" || GOTO :ERROR
COPY "RestartWebController.cmd" "%BUILDS_PATH%\\%BUILD_FULL_SIGNATURE%\\RestartWebController.cmd" || GOTO :ERROR

ECHO.
ECHO Done. Build %BUILD_FULL_SIGNATURE% successfully created.

:DONE
ECHO.
ECHO Done.
SET /p answer=Press any button to continue...
EXIT /b 0

:ERROR
ECHO.
ECHO Build failed.
SET /p answer=Press any button to continue...
EXIT /b %errorlevel%
