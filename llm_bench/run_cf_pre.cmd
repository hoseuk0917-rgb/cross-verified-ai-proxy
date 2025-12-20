@echo off
setlocal
if "%CF_API_TOKEN%"=="" (echo [ERR] CF_API_TOKEN not set & exit /b 1)
if "%CF_ACCOUNT_ID%"=="" (echo [ERR] CF_ACCOUNT_ID not set & exit /b 1)
if "%~1"=="" (echo Usage: run_cf.cmd payload.json out.json & exit /b 1)

set PAY=%~1
set OUT=%~2
if "%OUT%"=="" set OUT=out_cf.json

curl -sS -w "\nTIME_TOTAL=%{time_total}\nHTTP=%{http_code}\n" ^
  "https://api.cloudflare.com/client/v4/accounts/%CF_ACCOUNT_ID%/ai/run/@cf/meta/llama-3.1-8b-instruct" ^
  -H "Authorization: Bearer %CF_API_TOKEN%" ^
  -H "Content-Type: application/json" ^
  --data-binary @%PAY% ^
  > %OUT%

type %OUT%
endlocal
