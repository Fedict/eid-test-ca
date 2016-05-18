:: sign the fromcard exe
:: =====================

set FROMCARDINSTALLPATH=%~dp0..\..\Release
@echo FROMCARDINSTALLPATH = %FROMCARDINSTALLPATH% 

@set SIGNTOOL_PATH=C:\Program Files (x86)\Windows Kits\8.1\bin\x64

@echo [INFO] Sign the fromcard executable
"%SIGNTOOL_PATH%\signtool" sign /as /fd SHA1 /ac "%~dp0\MSCV-GlobalSign Root CA.cer" /s MY /n "Fedict" /sha1 "2259EF223A51E91964D7F4695706091194E018BB" /tr http://timestamp.globalsign.com/?signature=sha2 /v "%FROMCARDINSTALLPATH%\FromCard.exe"
"%SIGNTOOL_PATH%\signtool" sign /as /fd SHA256 /ac "%~dp0\MSCV-GlobalSign Root CA.cer" /s MY /n "Fedict" /sha1 "2259EF223A51E91964D7F4695706091194E018BB" /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 /v "%FROMCARDINSTALLPATH%\FromCard.exe"

@if "%ERRORLEVEL%" == "1" goto signtool_failed

goto end_resetpath

:signtool_failed
@echo [ERR ] signtool failed
@goto err

:end_resetpath
@cd %OUR_CURRENT_PATH%

@echo [INFO] Build_all Done...
@goto end

:err
@exit /b 1

:end

