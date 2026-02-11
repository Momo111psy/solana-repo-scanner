# 🛡️ Solana Repository Security Scanner

A comprehensive security analysis tool for GitHub repositories in the Solana ecosystem. Detects scams, abandoned projects, copy-pasted code, and security red flags through automated analysis of commit patterns, community engagement, and code metrics.

[![CI](https://github.com/Momo111psy/solana-repo-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Momo111psy/solana-repo-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Solana](https://img.shields.io/badge/Solana-Ecosystem-9945FF?logo=solana)](https://solana.com)

---

## 🎯 What It Does

This tool analyzes GitHub repositories and provides a comprehensive **risk score (0-100)** based on multiple security indicators:

### Detection Capabilities

- **Commit Pattern Analysis** - Identifies suspiciously low commit counts and abandoned projects
- **Code-to-Commit Ratio** - Detects copy-pasted projects with unrealistic LOC-per-commit ratios
- **Community Engagement** - Evaluates stars, forks, and community validation
- **Marketing Language Detection** - Flags excessive buzzwords and funding-seeking language
- **Solana-Specific Checks** - Verifies presence of Anchor.toml, Cargo.toml, and proper project structure
- **License & Documentation** - Checks for proper licensing and README quality
- **Contributor Analysis** - Identifies single-contributor patterns that may indicate copied work
- **Activity Monitoring** - Tracks last commit date and project abandonment

---

## 🚨 Why This Tool Exists

While researching Solana security projects, I discovered a repository claiming to be an **"AI-powered security tool"** with **139,043 lines of code** but only **2 commits**. This is physically impossible for legitimate development.

Someone had copy-pasted a massive codebase and claimed it as their own work to appear credible for grant applications. This tool was built to catch exactly that kind of scam and protect the Solana ecosystem from fraudulent projects.

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip3 package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/Momo111psy/solana-repo-scanner.git
cd solana-repo-scanner

# Install dependencies
pip3 install -r requirements.txt
```

---

## 🚀 Usage

### Basic Analysis

```bash
python3 analyze.py <github_url>
```

### Example: Analyzing a Suspicious Project

```bash
python3 analyze.py https://github.com/Momo111psy/solguard-ai
```

**Sample Output:**

```
======================================================================
🛡️  SOLANA REPOSITORY SECURITY ANALYSIS
======================================================================

📦 Repository: Momo111psy/solguard-ai
🔗 URL: https://github.com/Momo111psy/solguard-ai

🚨 RISK SCORE: 25/100 (HIGH RISK)
======================================================================

🚩 RED FLAGS DETECTED (6):

  1. Only 2 commits - extremely suspicious
  2. 0 stars - no community validation
  3. 0 forks - no community contribution or trust
  4. Extreme code-to-commit ratio: 69,521 LOC/commit (139,043 LOC ÷ 2 commits) - likely copy-pasted
  5. No README.md found - poor documentation
  6. No license - unprofessional or incomplete project

======================================================================
📊 REPOSITORY METADATA:
  • Stars: 0
  • Forks: 0
  • Watchers: 0
  • Open Issues: 0
  • Commits: 2
  • Language: Rust
  • Created: 2026-02-11
  • Last Updated: 2026-02-11
  • License: None
  • Is Fork: No
======================================================================
```

### Example: Analyzing Legitimate Projects

```bash
python3 analyze.py https://github.com/solana-labs/solana
```

**Sample Output:**

```
======================================================================
🛡️  SOLANA REPOSITORY SECURITY ANALYSIS
======================================================================

📦 Repository: solana-labs/solana
🔗 URL: https://github.com/solana-labs/solana

✅ RISK SCORE: 95/100 (LOW RISK)
======================================================================

✅ No major red flags detected - Project appears legitimate

======================================================================
📊 REPOSITORY METADATA:
  • Stars: 12,847
  • Forks: 4,123
  • Watchers: 12,847
  • Open Issues: 1,234
  • Commits: 23,456
  • Language: Rust
  • Created: 2018-02-13
  • Last Updated: 2026-02-11
  • License: Apache License 2.0
  • Is Fork: No
======================================================================
```

---

## 📊 Risk Scoring System

The tool assigns a risk score from **0-100** based on weighted factors:

| Score Range | Risk Level | Indicator | Description |
|-------------|------------|-----------|-------------|
| **80-100** | ✅ LOW RISK | Safe | Legitimate project with healthy development patterns |
| **60-79** | ⚠️ MEDIUM-LOW RISK | Caution | Minor concerns, generally safe but review recommended |
| **40-59** | ⚠️ MEDIUM-HIGH RISK | Warning | Multiple concerns, manual review required |
| **20-39** | 🚨 HIGH RISK | Danger | Significant red flags, likely scam or abandoned |
| **0-19** | 🔴 CRITICAL RISK | Avoid | Extreme red flags, almost certainly fraudulent |

### Scoring Penalties

| Red Flag | Score Penalty |
|----------|---------------|
| Extreme code-to-commit ratio (>50k LOC/commit) | -40 |
| Only 1-2 commits | -35 |
| Abandoned (>365 days since last commit) | -30 |
| Token sale/ICO language detected | -25 |
| High code-to-commit ratio (>10k LOC/commit) | -25 |
| Only 3-9 commits | -25 |
| Stale project (>180 days inactive) | -20 |
| 0 stars | -20 |
| Claims to be Solana but missing key files | -20 |
| Heavy funding-seeking language | -20 |
| Heavy marketing language | -15 |
| 0 forks | -15 |
| No README found | -15 |
| Elevated code-to-commit ratio (>5k LOC/commit) | -15 |
| Single contributor with many commits | -15 |
| 10-24 commits | -15 |
| Funding-seeking language | -12 |
| Repository is a fork | -10 |
| No license | -10 |
| Very short README (<200 chars) | -10 |
| Inactive (>90 days) | -10 |
| Marketing buzzwords in description | -8 |

---

## 🔍 Detection Examples

### Red Flag: Copy-Pasted Code

A project with **100,000+ lines of code** but only **3 commits** is flagged as **"likely copy-pasted"** because:

- Realistic development: **50-500 LOC per commit**
- This project: **33,333 LOC per commit** (100,000 ÷ 3)
- **Conclusion:** Code was copied from elsewhere, not developed organically

### Red Flag: Abandoned Project

A project with the last commit **400 days ago** is flagged as **"abandoned"** because:

- Active projects: Commits within **30-90 days**
- This project: **No activity for over a year**
- **Conclusion:** Project is no longer maintained, potential security risk

### Red Flag: Marketing-Heavy Description

A description with phrases like **"revolutionary," "world's first," "game-changing," "10x performance"** is flagged because:

- Legitimate projects: Focus on **technical details**
- Scam projects: Use **excessive marketing buzzwords**
- **Conclusion:** More marketing than substance

---

## 🧪 Running Tests

The project includes a comprehensive test suite covering unit tests, integration tests, and edge cases.

```bash
# Run all tests
python3 tests/test_scanner.py

# Run with pytest (more detailed output)
pytest tests/test_scanner.py -v
```

### Test Coverage

- **URL Parsing** - Valid/invalid URLs, edge cases
- **Risk Level Calculation** - Score boundaries, categorization
- **Security Checks** - Commit patterns, code ratios, community metrics
- **Integration Tests** - Real-world repository analysis
- **Error Handling** - Non-existent repos, API failures

---

## 🔧 Technical Details

### How It Works

The scanner uses the **GitHub REST API** (no authentication required for basic analysis) to:

1. **Fetch repository metadata** - Stars, forks, creation date, license
2. **Analyze commit history** - Count commits, check patterns, identify contributors
3. **Calculate lines of code** - Detect unrealistic code-to-commit ratios
4. **Scan README content** - Identify marketing language and funding requests
5. **Verify Solana indicators** - Check for Anchor.toml, Cargo.toml, package.json
6. **Generate risk score** - Weighted scoring based on multiple factors

### API Rate Limits

- **Unauthenticated requests:** 60 requests per hour per IP
- **Authenticated requests:** 5,000 requests per hour (requires GitHub token)

To use authenticated requests (optional):

```bash
export GITHUB_TOKEN="your_github_personal_access_token"
```

Then modify `analyze.py` to include the token in API requests:

```python
headers = {"Authorization": f"token {os.getenv('GITHUB_TOKEN')}"}
response = requests.get(api_url, headers=headers)
```

---

## 🎯 Use Cases

### 1. Due Diligence Before Investment

Before investing in or using a Solana project, run this tool to identify red flags:

```bash
python3 analyze.py https://github.com/some-project/token-sale
```

### 2. Grant Application Review

Grant committees can use this tool to verify the legitimacy of applicant repositories:

```bash
python3 analyze.py https://github.com/applicant/grant-project
```

### 3. Bug Bounty Research

Security researchers can identify potentially vulnerable or abandoned projects:

```bash
python3 analyze.py https://github.com/target/vulnerable-project
```

### 4. Community Protection

Help others avoid scam projects by sharing analysis results:

```bash
python3 analyze.py https://github.com/scam/fake-project > analysis_report.txt
```

---

## 🚧 Limitations

- **No authentication** - Limited to 60 API requests per hour without GitHub token
- **Public repos only** - Cannot analyze private repositories
- **Basic analysis** - Does not perform deep code quality checks or vulnerability scanning
- **GitHub-only** - Does not analyze GitLab, Bitbucket, or other platforms
- **No real-time monitoring** - Snapshot analysis only, not continuous monitoring

---

## 🛣️ Roadmap

### Planned Features

- [ ] **GitHub token authentication** - Higher rate limits and private repo access
- [ ] **Recent activity analysis** - Track commit frequency over time
- [ ] **Contributor diversity checks** - Identify single-developer projects
- [ ] **Code quality metrics** - Linting, test coverage, documentation quality
- [ ] **Solana-specific security checks** - Anchor program analysis, common vulnerabilities
- [ ] **HTML/PDF report generation** - Professional reports for due diligence
- [ ] **CI/CD integration** - GitHub Actions workflow for automated scanning
- [ ] **Web interface** - Browser-based tool for non-technical users
- [ ] **Historical tracking** - Monitor repository changes over time
- [ ] **Batch analysis** - Scan multiple repositories at once

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report bugs** - Open an issue describing the problem
2. **Suggest features** - Open an issue with your idea
3. **Submit pull requests** - Fork the repo, make changes, and submit a PR
4. **Improve documentation** - Fix typos, add examples, clarify instructions
5. **Add test cases** - Expand test coverage for edge cases

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/solana-repo-scanner.git
cd solana-repo-scanner

# Install dependencies
pip3 install -r requirements.txt

# Run tests to ensure everything works
python3 tests/test_scanner.py

# Make your changes and submit a PR
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

You are free to:
- ✅ Use this tool for personal or commercial purposes
- ✅ Modify and distribute the code
- ✅ Include it in your own projects

---

## ⚠️ Disclaimer

This tool provides **automated analysis based on public GitHub data**. It should be used as **one factor in security assessment**, not the sole determining factor.

**Always perform thorough manual review** before making decisions based on this tool's output. The tool does not:

- Perform deep code audits
- Detect all types of vulnerabilities
- Guarantee the security or legitimacy of any project
- Replace professional security audits

Use at your own risk. The authors are not responsible for any decisions made based on this tool's analysis.

---

## 🙏 Acknowledgments

Built by someone tired of scam projects in the Solana ecosystem. Special thanks to:

- **Solana Labs** - For building an amazing blockchain ecosystem
- **Coral (Anchor)** - For making Solana development accessible
- **GitHub** - For providing a free API for repository analysis
- **The Solana Community** - For supporting legitimate projects and calling out scams

---

## 📞 Contact

- **GitHub:** [@Momo111psy](https://github.com/Momo111psy)
- **Issues:** [Report a bug or request a feature](https://github.com/Momo111psy/solana-repo-scanner/issues)

---

**Built to protect the Solana ecosystem from fraudulent projects.** 🛡️

If this tool helped you avoid a scam or identify a legitimate project, consider giving it a ⭐ on GitHub!
