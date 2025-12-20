@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

del /q bench_times.tsv 2>nul

for /l %%i in (1,1,10) do (
  echo --- RUN %%i ---

  curl -sS -o out_groq_pre_%%i.json  -w "GROQ_PRE	%%i	%%{http_code}	%%{time_total}\n"  https://api.groq.com/openai/v1/chat/completions -H "Authorization: Bearer %GROQ_API_KEY%" -H "Content-Type: application/json" --data-binary @payload_groq_pre.json  >> bench_times.tsv
  timeout /t 2 /nobreak >nul

  curl -sS -o out_gemini_pre_%%i.json -w "GEM_PRE	%%i	%%{http_code}	%%{time_total}\n" "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%GEMINI_API_KEY%" -H "Content-Type: application/json" --data-binary @payload_gemini_pre.json >> bench_times.tsv
  timeout /t 2 /nobreak >nul

  curl -sS -o out_cf_pre_%%i.json    -w "CF_PRE	%%i	%%{http_code}	%%{time_total}\n"   "https://api.cloudflare.com/client/v4/accounts/%CF_ACCOUNT_ID%/ai/run/@cf/meta/llama-3.1-8b-instruct" -H "Authorization: Bearer %CF_API_TOKEN%" -H "Content-Type: application/json" --data-binary @payload_cf_pre.json >> bench_times.tsv
  timeout /t 2 /nobreak >nul

  curl -sS -o out_groq_post_%%i.json  -w "GROQ_POST	%%i	%%{http_code}	%%{time_total}\n"  https://api.groq.com/openai/v1/chat/completions -H "Authorization: Bearer %GROQ_API_KEY%" -H "Content-Type: application/json" --data-binary @payload_groq_post.json  >> bench_times.tsv
  timeout /t 2 /nobreak >nul

  curl -sS -o out_gemini_post_%%i.json -w "GEM_POST	%%i	%%{http_code}	%%{time_total}\n" "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%GEMINI_API_KEY%" -H "Content-Type: application/json" --data-binary @payload_gemini_post.json >> bench_times.tsv
  timeout /t 2 /nobreak >nul

  curl -sS -o out_cf_post_%%i.json    -w "CF_POST	%%i	%%{http_code}	%%{time_total}\n"   "https://api.cloudflare.com/client/v4/accounts/%CF_ACCOUNT_ID%/ai/run/@cf/meta/llama-3.1-8b-instruct" -H "Authorization: Bearer %CF_API_TOKEN%" -H "Content-Type: application/json" --data-binary @payload_cf_post.json >> bench_times.tsv
  timeout /t 4 /nobreak >nul
)

echo.
echo ==== DONE ====
type bench_times.tsv
endlocal
