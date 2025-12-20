$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$p = Get-Content -Raw -Encoding UTF8 ".\post_prompt_case1.txt"

$o = @{
  messages = @(
    @{ role = "system"; content = "Return ONLY a single JSON object. No markdown. No code fences. Output must be valid JSON." },
    @{ role = "user";   content = $p }
  )
  temperature = 0
  max_tokens  = 900
}

$o | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 ".\payload_cf_post.json"
Write-Host "OK wrote payload_cf_post.json"
