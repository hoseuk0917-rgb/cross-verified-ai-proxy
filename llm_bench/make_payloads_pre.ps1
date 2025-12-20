$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

Write-Host "[1] start"

function Write-Utf8NoBom([string]$path, [string]$text) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
}

Write-Host "[2] read pre_prompt_case1.txt"
$prePath = Join-Path $PSScriptRoot 'pre_prompt_case1.txt'
if (!(Test-Path -LiteralPath $prePath)) { throw "Missing: $prePath" }

$pre = Get-Content -LiteralPath $prePath -Raw
if (-not $pre -or -not $pre.Trim()) { throw "pre_prompt_case1.txt is empty" }

Write-Host "[3] build groq json"
$payloadGroq = @{
  model = "llama-3.3-70b-versatile"
  temperature = 0.1
  messages = @(@{ role = "user"; content = $pre })
} | ConvertTo-Json -Depth 20

Write-Host "[4] write payload_groq_pre.json"
Write-Utf8NoBom (Join-Path $PSScriptRoot "payload_groq_pre.json") $payloadGroq

Write-Host "[5] build gemini json"
$payloadGemini = @{
  contents = @(@{ role = "user"; parts = @(@{ text = $pre }) })
  generationConfig = @{ temperature = 0.1 }
} | ConvertTo-Json -Depth 20

Write-Host "[6] write payload_gemini_pre.json"
Write-Utf8NoBom (Join-Path $PSScriptRoot "payload_gemini_pre.json") $payloadGemini

Write-Host "[7] build cf json"
$payloadCF = @{
  messages = @(@{ role = "user"; content = $pre })
} | ConvertTo-Json -Depth 20

Write-Host "[8] write payload_cf_pre.json"
Write-Utf8NoBom (Join-Path $PSScriptRoot "payload_cf_pre.json") $payloadCF

Write-Host "[9] DONE"
exit 0
