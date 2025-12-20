@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ===========================
rem Config (필요시 너 환경변수명에 맞게만 수정)
rem ===========================
if "%GROQ_API_KEY%"=="" (
  echo [ERR] Missing GROQ_API_KEY
  exit /b 1
)
if "%GEMINI_API_KEY%"=="" (
  echo [ERR] Missing GEMINI_API_KEY
  exit /b 1
)
if "%CF_API_TOKEN%"=="" (
  echo [ERR] Missing CF_API_TOKEN
  exit /b 1
)
if "%CF_ACCOUNT_ID%"=="" (
  echo [ERR] Missing CF_ACCOUNT_ID
  exit /b 1
)
if "%CF_MODEL%"=="" (
  rem default
  set "CF_MODEL=@cf/meta/llama-3.1-8b-instruct"
)

set "DIR=%~dp0"
set "TIMES=%DIR%bench_times_post_case2.tsv"

rem payload 파일(이미 make_payloads_post.cjs로 만들어졌다고 가정)
set "PG=%DIR%payload_groq_post.json"
set "PM=%DIR%payload_gemini_post.json"
set "PC=%DIR%payload_cf_post.json"

if not exist "%PG%" ( echo [ERR] Missing %PG% & exit /b 1 )
if not exist "%PM%" ( echo [ERR] Missing %PM% & exit /b 1 )
if not exist "%PC%" ( echo [ERR] Missing %PC% & exit /b 1 )

rem 선택: run 횟수 (기본 10)
set "N=%~1"
if "%N%"=="" set "N=10"

echo === RUN POST CASE2 (N=%N%) ===
echo times log: %TIMES%
echo.

for /l %%i in (1,1,%N%) do (
  echo ---- RUN %%i/%N% ----

  call :CALL_GROQ %%i
  timeout /t 2 /nobreak >nul

  call :CALL_GEMINI %%i
  timeout /t 2 /nobreak >nul

  call :CALL_CF %%i
  timeout /t 2 /nobreak >nul
)

echo.
echo OK: finished. out_*_post_#.json created + bench_times_post_case2.tsv updated
exit /b 0


:CALL_GROQ
set "RUN=%~1"
set "OUT=%DIR%out_groq_post_%RUN%.json"
set "URL=https://api.groq.com/openai/v1/chat/completions"

for /f "delims=" %%A in ('
  curl -sS -o "%OUT%" -w "HTTP=%%{http_code} TIME=%%{time_total}" ^
    -H "Authorization: Bearer %GROQ_API_KEY%" ^
    -H "Content-Type: application/json" ^
    --data-binary @"%PG%" ^
    "%URL%"
') do set "META=%%A"

call :PARSE_META "!META!" CODE TSEC
echo GROQ_POST^|%RUN%^|!CODE!^|!TSEC!>> "%TIMES%"

echo [GROQ] run=%RUN% http=!CODE! t=!TSEC! out=%OUT%
exit /b 0


:CALL_GEMINI
set "RUN=%~1"
set "OUT=%DIR%out_gemini_post_%RUN%.json"
set "MODEL=gemini-2.0-flash"
set "URL=https://generativelanguage.googleapis.com/v1beta/models/%MODEL%:generateContent?key=%GEMINI_API_KEY%"

rem 1st try
for /f "delims=" %%A in ('
  curl -sS -o "%OUT%" -w "HTTP=%%{http_code} TIME=%%{time_total}" ^
    -H "Content-Type: application/json" ^
    --data-binary @"%PM%" ^
    "%URL%"
') do set "META=%%A"

call :PARSE_META "!META!" CODE TSEC

rem 429이면 10초 쉬고 1회 재시도(최소 백오프)
if "!CODE!"=="429" (
  echo [GEMINI] 429 detected. backoff 10s then retry once...
  timeout /t 10 /nobreak >nul

  for /f "delims=" %%A in ('
    curl -sS -o "%OUT%" -w "HTTP=%%{http_code} TIME=%%{time_total}" ^
      -H "Content-Type: application/json" ^
      --data-binary @"%PM%" ^
      "%URL%"
  ') do set "META=%%A"

  call :PARSE_META "!META!" CODE TSEC
)

echo GEM_POST^|%RUN%^|!CODE!^|!TSEC!>> "%TIMES%"
echo [GEM] run=%RUN% http=!CODE! t=!TSEC! out=%OUT%
exit /b 0


:CALL_CF
set "RUN=%~1"
set "OUT=%DIR%out_cf_post_%RUN%.json"
set "URL=https://api.cloudflare.com/client/v4/accounts/%CF_ACCOUNT_ID%/ai/run/%CF_MODEL%"

for /f "delims=" %%A in ('
  curl -sS -o "%OUT%" -w "HTTP=%%{http_code} TIME=%%{time_total}" ^
    -H "Authorization: Bearer %CF_API_TOKEN%" ^
    -H "Content-Type: application/json" ^
    --data-binary @"%PC%" ^
    "%URL%"
') do set "META=%%A"

call :PARSE_META "!META!" CODE TSEC
echo CF_POST^|%RUN%^|!CODE!^|!TSEC!>> "%TIMES%"

echo [CF] run=%RUN% http=!CODE! t=!TSEC! out=%OUT%
exit /b 0


:PARSE_META
rem input: "HTTP=200 TIME=0.123"
set "S=%~1"
set "%2=0"
set "%3=0"
for /f "tokens=1,2 delims= " %%x in ("%S%") do (
  for /f "tokens=2 delims==" %%p in ("%%x") do set "%2=%%p"
  for /f "tokens=2 delims==" %%q in ("%%y") do set "%3=%%q"
)
exit /b 0
