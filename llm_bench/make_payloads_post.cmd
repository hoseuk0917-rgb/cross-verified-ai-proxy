@echo off
setlocal
powershell -NoProfile -Command ^
  "$post=Get-Content .\post_prompt_case1.txt -Raw; ^
   $o=@{model='llama-3.3-70b-versatile'; temperature=0.1; messages=@(@{role='user'; content=$post})} | ConvertTo-Json -Depth 10; ^
   Set-Content -Encoding utf8 .\payload_groq_post.json $o"

powershell -NoProfile -Command ^
  "$post=Get-Content .\post_prompt_case1.txt -Raw; ^
   $o=@{contents=@(@{role='user'; parts=@(@{text=$post})}); generationConfig=@{temperature=0.1}} | ConvertTo-Json -Depth 10; ^
   Set-Content -Encoding utf8 .\payload_gemini_post.json $o"

powershell -NoProfile -Command ^
  "$post=Get-Content .\post_prompt_case1.txt -Raw; ^
   $o=@{prompt=$post} | ConvertTo-Json -Depth 10; ^
   Set-Content -Encoding utf8 .\payload_cf_post.json $o"

echo OK: payload_*_post.json created
endlocal
