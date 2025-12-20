@echo off
setlocal
if "%GROQ_API_KEY%"=="" (echo [ERR] GROQ_API_KEY not set & exit /b 1)
if "%~1"=="" (echo Usage: run_groq.cmd payload.json out.json & exit /b 1)

set PAY=%~1
set OUT=%~2
if "%OUT%"=="" set OUT=out_groq.json

curl -sS -w "\nTIME_TOTAL=%{time_total}\nHTTP=%{http_code}\n" ^
  https://api.groq.com/openai/v1/chat/completions ^
  -H "Authorization: Bearer %GROQ_API_KEY%" ^
  -H "Content-Type: application/json" ^
  --data-binary @%PAY% ^
  > %OUT%

type %OUT%
endlocal
