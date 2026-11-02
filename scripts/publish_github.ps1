param([string]$Name = "vuln-skill")
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot ".."))
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "Install Git first." }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "Install GitHub CLI: https://cli.github.com/" }
gh auth status
if ($LASTEXITCODE -ne 0) { throw "Run gh auth login before publishing." }
if (-not (Test-Path .git)) { git init }
git add .
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) { git commit -m "Initial Vuln-Skill research prototype" }
git branch -M main
$existing = git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0) { throw "An origin remote already exists. Inspect 'git remote -v' first." }
gh repo create $Name --public --source . --remote origin --push
if ($LASTEXITCODE -ne 0) { throw "GitHub CLI failed. Check gh auth status and the repository name." }
