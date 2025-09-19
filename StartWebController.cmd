@echo off
cd WebController
if "%1"=="" (
	set c3webcontroller_url="http://localhost:52935"
) else (
	set c3webcontroller_url=%1
)
dotnet C3WebController.dll --urls %c3webcontroller_url%
