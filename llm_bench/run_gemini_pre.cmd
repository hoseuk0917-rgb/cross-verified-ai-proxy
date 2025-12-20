@echo off
setlocal
if "%GEMINI_API_KEY%"=="" (echo [ERR] GEMINI_API_KEY not set & exit /b 1)
if "%~1"=="" (echo Usage: run_gemini.cmd payload.json out.json & exit /b 1)

set PAY=%~1
set OUT=%~2
if "%OUT%"=="" set OUT=out_gemini.json

curl -sS -w "\nTIME_TOTAL=%{time_total}\nHTTP=%{http_code}\n" ^
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%GEMINI_API_KEY%" ^
  -H "Content-Type: application/json" ^
  --data-binary @%PAY% ^
  > %OUT%

type %OUT%
endlocal
