# Publish this Repository to GitHub

## Recommended: GitHub CLI (works on Windows, macOS and Linux)

1. Download the source ZIP from ChatGPT and **extract it**.
2. Install Git and [GitHub CLI (`gh`)](https://cli.github.com/).
3. Open PowerShell or Terminal inside the extracted `vuln-skill` repository folder.
4. Authenticate:

   ```bash
   gh auth login
   ```

5. Option A — use the ready-to-run helper:

   Windows PowerShell:

   ```powershell
   .\scripts\publish_github.ps1 -Name vuln-skill
   ```

   Linux / macOS:

   ```bash
   bash scripts/publish_github.sh vuln-skill
   ```

   The helper creates a local commit and asks GitHub CLI to create and push a public repository. It never stores tokens or secrets in the repository.

6. Option B — run the commands yourself:

   ```bash
   git init
   git add .
   git commit -m "Initial Vuln-Skill research prototype"
   git branch -M main
   gh repo create vuln-skill --public --source . --remote origin --push
   ```

If Git asks you to set your identity, run `git config --global user.name "Your Name"` and `git config --global user.email "your-email@example.com"` with your own information, then repeat the commit.

## Alternative: upload to an existing empty repository with Git

Create an empty repository on GitHub **without prepopulating a README, license or .gitignore**. From your extracted folder:

```bash
git init
git add .
git commit -m "Initial Vuln-Skill research prototype"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/vuln-skill.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your own GitHub login. Authentication is handled by GitHub CLI, Git Credential Manager, or your configured SSH credentials; do not embed personal access tokens in URLs.

## Suggested repository settings

- **Repository name:** `vuln-skill`
- **Description:** `From CVEs to verified, locally executable vulnerability investigation Skills. CREATE -> VERIFY -> INVESTIGATE.`
- **Topics:** `cve`, `security-automation`, `vulnerability-management`, `llm`, `incident-response`, `open-source`, `agent-skills`
- **License:** Apache-2.0 (already included)
- **Visibility:** Public when ready; use private only for pre-release review if your CFP permits.
- **Default branch:** main
- **Actions:** enable CI; workflow supplied in `.github/workflows/tests.yml`.

## Submit to Black Hat Arsenal

Copy the final GitHub URL, e.g. `https://github.com/YOUR_USERNAME/vuln-skill`, into the CFP **Source Code** field. Confirm the Review Board has access. The README provides the problem statement, technical operation, offline reproduction, and limitations; `docs/ARSENAL_DEMO.md` is a time-boxed demonstration script.

## Never upload

- `.env` or real OpenAI API keys
- credentials or private network information
- production logs, source code or customer SBOMs
- private test targets or unredacted vulnerability evidence

The `.gitignore` excludes `.env`, `.venv`, generated output and test caches. Always inspect `git status` before pushing.
