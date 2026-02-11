# Solana Repository Security Scanner

A lightweight security analysis tool for GitHub repositories in the Solana ecosystem. Detects red flags that may indicate scam projects, abandoned repos, or low-quality code.

## What It Does

Analyzes GitHub repositories and provides a risk score (0-100) based on:
- Commit patterns and frequency
- Code-to-commit ratio (detects copy-pasted projects)
- Community engagement (stars, forks)
- Marketing language in README
- Funding-seeking patterns

## Why I Built This

While researching Solana security projects, I discovered **SolGuard AI** - a project claiming to be an "AI-powered security tool" with 139,043 lines of code. Sounds impressive, right?

**The problem:** It only had **2 commits**.

That's physically impossible for legitimate development. Someone copy-pasted a massive codebase and claimed it as their own. This tool was built to catch exactly that kind of scam.

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/solana-repo-scanner.git
cd solana-repo-scanner

# Install dependencies
pip3 install -r requirements.txt
```

## Usage

```bash
python3 analyze.py <github_url>
```

### Example: Analyzing a Scam Project

```bash
python3 analyze.py https://github.com/Momo111psy/solguard-ai
```

**Output:**
```
========================================
GitHub Repository Security Analysis
========================================

Repository: Momo111psy/solguard-ai
Analyzing: https://github.com/Momo111psy/solguard-ai

----------------------------------------
RISK SCORE: 15/100
RISK LEVEL: HIGH RISK
----------------------------------------

RED FLAGS DETECTED:
  - Only 2 commits - suspiciously low for a real project
  - 0 stars - no community interest or validation
  - 0 forks - no community contribution or trust
  - Only 2 commits for 139043 lines of code - likely copy-pasted

ANALYSIS COMPLETE
========================================
```

### Example: Analyzing Legitimate Projects

```bash
python3 analyze.py https://github.com/solana-labs/solana
```

**Output:**
```
========================================
RISK SCORE: 100/100
RISK LEVEL: LOW RISK
----------------------------------------
No red flags detected.
```

```bash
python3 analyze.py https://github.com/coral-xyz/anchor
```

**Output:**
```
========================================
RISK SCORE: 100/100
RISK LEVEL: LOW RISK
----------------------------------------
No red flags detected.
```

## How It Works

The tool uses the GitHub API (no authentication required for basic analysis) to:

1. **Fetch repository metadata** - stars, forks, creation date
2. **Analyze commit history** - count commits, check patterns
3. **Calculate lines of code** - detect unrealistic code-to-commit ratios
4. **Scan README content** - identify marketing language and funding requests
5. **Generate risk score** - weighted scoring based on multiple factors

### Risk Scoring

- **70-100**: LOW RISK - Legitimate project with healthy development patterns
- **40-69**: MEDIUM RISK - Some concerns, requires manual review
- **0-39**: HIGH RISK - Multiple red flags detected, likely scam or abandoned

## Red Flags Detected

- ✅ Low commit count (< 10 commits)
- ✅ No community engagement (0 stars/forks)
- ✅ Unrealistic code-to-commit ratio (copy-pasted projects)
- ✅ Marketing language ("revolutionary", "game-changing", "next-generation")
- ✅ Funding-seeking language ("donate", "support us", "buy our token")

## Limitations

- **No authentication** - Limited to 60 API requests per hour
- **Public repos only** - Cannot analyze private repositories
- **Basic analysis** - Does not perform deep code quality checks
- **GitHub-only** - Does not analyze GitLab, Bitbucket, or other platforms

## Future Improvements

- [ ] GitHub token authentication for higher rate limits
- [ ] Recent activity analysis (last commit date)
- [ ] Contributor diversity checks
- [ ] Code quality metrics (linting, test coverage)
- [ ] Integration with Solana-specific security checks
- [ ] HTML/PDF report generation

## Use Cases

- **Due diligence** - Before investing in or using a Solana project
- **Bug bounty research** - Identify potentially vulnerable projects
- **Security auditing** - Quick initial assessment of project health
- **Community protection** - Help others avoid scam projects

## Contributing

Found a bug? Have a feature request? Open an issue or submit a pull request!

## License

MIT License - feel free to use, modify, and distribute.

## Disclaimer

This tool provides automated analysis based on public GitHub data. It should be used as one factor in security assessment, not the sole determining factor. Always perform thorough manual review before making decisions based on this tool's output.

---

**Built by someone tired of scam projects in the Solana ecosystem.** 🛡️
