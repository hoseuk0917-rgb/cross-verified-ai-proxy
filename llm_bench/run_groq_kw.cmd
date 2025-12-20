@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

if "%GROQ_API_KEY%"=="" (
  echo [ERR] Missing GROQ_API_KEY
  exit /b 1
)

set PAY=%CD%\payload_kw_groq.json
if not exist "%PAY%" (
  echo [ERR] Missing %PAY%
  exit /b 1
)

set N=%1
if "%N%"=="" set N=5

echo === RUN GROQ KW (N=%N%) ===

for /l %%i in (1,1,%N%) do (
  echo ---- RUN %%i/%N% ----
  curl -sS -o "out_groq_kw_%%i.json" -w "HTTP=%%{http_code} TIME=%%{time_total}\n" ^
    https://api.groq.com/openai/v1/chat/completions ^
    -H "Authorization: Bearer %GROQ_API_KEY%" ^
    -H "Content-Type: application/json" ^
    --data-binary @"%PAY%"
  timeout /t 2 /nobreak >nul
)

echo OK: out_groq_kw_#.json created
endlocal
