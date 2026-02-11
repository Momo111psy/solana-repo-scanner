#!/usr/bin/env python3
"""
Solana Repository Security Scanner
Advanced tool for analyzing GitHub repositories in the Solana ecosystem
Detects scams, abandoned projects, and security red flags
"""

import requests
import re
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Tuple


class SolanaRepoScanner:
    """Main scanner class for analyzing Solana GitHub repositories"""
    
    def __init__(self, repo_url: str):
        self.repo_url = repo_url
        self.owner = None
        self.repo = None
        self.repo_data = None
        self.commits = []
        self.red_flags = []
        self.score = 100
        
    def parse_url(self) -> bool:
        """Parse GitHub URL to extract owner and repo name"""
        match = re.search(r"github\.com/([^/]+)/([^/]+)", self.repo_url)
        if not match:
            print("❌ Invalid GitHub URL format")
            return False
        
        self.owner = match.group(1)
        self.repo = match.group(2).replace(".git", "")
        return True
    
    def fetch_repo_data(self) -> bool:
        """Fetch repository metadata from GitHub API"""
        api_url = f"https://api.github.com/repos/{self.owner}/{self.repo}"
        try:
            response = requests.get(api_url, timeout=10)
            if response.status_code != 200:
                print(f"❌ Failed to fetch repository (Status: {response.status_code})")
                return False
            self.repo_data = response.json()
            return True
        except Exception as e:
            print(f"❌ Error fetching repository: {e}")
            return False
    
    def fetch_commits(self) -> bool:
        """Fetch commit history from GitHub API"""
        commits_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/commits"
        try:
            response = requests.get(commits_url, timeout=10)
            if response.status_code == 200:
                self.commits = response.json()
            return True
        except Exception as e:
            print(f"⚠️  Warning: Could not fetch commits: {e}")
            return False
    
    def check_commit_patterns(self):
        """Analyze commit patterns for suspicious activity"""
        commit_count = len(self.commits)
        
        # Check 1: Very low commit count
        if commit_count < 3:
            self.red_flags.append(f"Only {commit_count} commits - extremely suspicious")
            self.score -= 35
        elif commit_count < 10:
            self.red_flags.append(f"Only {commit_count} commits - suspiciously low for production code")
            self.score -= 25
        elif commit_count < 25:
            self.red_flags.append(f"{commit_count} commits - below average for established project")
            self.score -= 15
        
        # Check 2: Commit frequency and recency
        if self.commits:
            try:
                last_commit_date = datetime.strptime(
                    self.commits[0]['commit']['author']['date'], 
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                days_since_last_commit = (datetime.utcnow() - last_commit_date).days
                
                if days_since_last_commit > 365:
                    self.red_flags.append(f"Abandoned: Last commit was {days_since_last_commit} days ago")
                    self.score -= 30
                elif days_since_last_commit > 180:
                    self.red_flags.append(f"Stale: Last commit was {days_since_last_commit} days ago")
                    self.score -= 20
                elif days_since_last_commit > 90:
                    self.red_flags.append(f"Inactive: Last commit was {days_since_last_commit} days ago")
                    self.score -= 10
            except:
                pass
        
        # Check 3: Single contributor pattern (potential copy-paste)
        if commit_count >= 5:
            try:
                authors = set()
                for commit in self.commits[:50]:  # Check first 50 commits
                    author = commit['commit']['author']['email']
                    authors.add(author)
                
                if len(authors) == 1 and commit_count > 20:
                    self.red_flags.append("Single contributor with many commits - may indicate copied project")
                    self.score -= 15
            except:
                pass
    
    def check_community_engagement(self):
        """Analyze community metrics (stars, forks, watchers)"""
        stars = self.repo_data.get("stargazers_count", 0)
        forks = self.repo_data.get("forks_count", 0)
        watchers = self.repo_data.get("watchers_count", 0)
        open_issues = self.repo_data.get("open_issues_count", 0)
        
        # Check stars
        if stars == 0:
            self.red_flags.append("0 stars - no community validation")
            self.score -= 20
        elif stars < 5:
            self.red_flags.append(f"Only {stars} stars - minimal community interest")
            self.score -= 10
        
        # Check forks
        if forks == 0:
            self.red_flags.append("0 forks - no community contribution or trust")
            self.score -= 15
        
        # Check if repo is a fork itself
        if self.repo_data.get("fork", False):
            self.red_flags.append("Repository is a fork - may not be original work")
            self.score -= 10
    
    def check_code_to_commit_ratio(self):
        """Detect unrealistic code-to-commit ratios (copy-paste indicator)"""
        try:
            lang_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/languages"
            response = requests.get(lang_url, timeout=10)
            
            if response.status_code == 200:
                languages = response.json()
                total_loc = sum(languages.values())
                commit_count = len(self.commits)
                
                if total_loc > 0 and commit_count > 0:
                    loc_per_commit = total_loc / commit_count
                    
                    # Realistic range: 50-500 LOC per commit
                    # Anything above 10,000 LOC per commit is highly suspicious
                    if loc_per_commit > 50000:
                        self.red_flags.append(
                            f"Extreme code-to-commit ratio: {loc_per_commit:,.0f} LOC/commit "
                            f"({total_loc:,} LOC ÷ {commit_count} commits) - likely copy-pasted"
                        )
                        self.score -= 40
                    elif loc_per_commit > 10000:
                        self.red_flags.append(
                            f"High code-to-commit ratio: {loc_per_commit:,.0f} LOC/commit "
                            f"({total_loc:,} LOC ÷ {commit_count} commits) - suspicious"
                        )
                        self.score -= 25
                    elif loc_per_commit > 5000:
                        self.red_flags.append(
                            f"Elevated code-to-commit ratio: {loc_per_commit:,.0f} LOC/commit - review recommended"
                        )
                        self.score -= 15
        except Exception as e:
            pass
    
    def check_description_and_readme(self):
        """Scan description and README for marketing language and red flags"""
        # Check description
        description = self.repo_data.get("description", "").lower() if self.repo_data.get("description") else ""
        
        marketing_terms = [
            "world's first", "revolutionary", "game-changing", "unprecedented",
            "next-generation", "cutting-edge", "industry-leading", "paradigm shift",
            "disruptive", "groundbreaking", "80%", "10x", "100x"
        ]
        
        marketing_count = sum(1 for term in marketing_terms if term in description)
        if marketing_count >= 2:
            self.red_flags.append(f"Heavy marketing language in description ({marketing_count} buzzwords)")
            self.score -= 15
        elif marketing_count == 1:
            self.red_flags.append("Marketing buzzwords detected in description")
            self.score -= 8
        
        # Check README
        readme_url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/main/README.md"
        try:
            readme_response = requests.get(readme_url, timeout=10)
            if readme_response.status_code == 200:
                readme = readme_response.text.lower()
                
                # Funding-seeking language
                funding_keywords = [
                    "seeking", "grant", "subsidy", "funding", "donate", 
                    "support us", "contribute financially", "sponsorship"
                ]
                funding_count = sum(1 for keyword in funding_keywords if keyword in readme)
                
                if funding_count >= 3:
                    self.red_flags.append(f"Heavy funding-seeking language in README ({funding_count} instances)")
                    self.score -= 20
                elif funding_count >= 2:
                    self.red_flags.append("Funding-seeking language detected in README")
                    self.score -= 12
                
                # Check for token sale / ICO language
                token_keywords = ["buy our token", "token sale", "ico", "presale", "airdrop"]
                if any(keyword in readme for keyword in token_keywords):
                    self.red_flags.append("Token sale/ICO language detected - potential scam")
                    self.score -= 25
                
                # Check README length (too short = lazy, too long = marketing)
                readme_length = len(readme)
                if readme_length < 200:
                    self.red_flags.append("Very short README - insufficient documentation")
                    self.score -= 10
        except:
            # Try master branch if main doesn't exist
            readme_url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/master/README.md"
            try:
                readme_response = requests.get(readme_url, timeout=10)
                if readme_response.status_code != 200:
                    self.red_flags.append("No README.md found - poor documentation")
                    self.score -= 15
            except:
                pass
    
    def check_solana_specific_indicators(self):
        """Check Solana-specific security indicators"""
        try:
            # Check if it's actually a Solana project
            contents_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/contents"
            response = requests.get(contents_url, timeout=10)
            
            if response.status_code == 200:
                files = [item['name'] for item in response.json() if item['type'] == 'file']
                
                # Check for Solana indicators
                has_anchor = 'Anchor.toml' in files
                has_cargo = 'Cargo.toml' in files
                has_package_json = 'package.json' in files
                
                # If claiming to be Solana but missing key files
                description = self.repo_data.get("description", "").lower() if self.repo_data.get("description") else ""
                if "solana" in description or "solana" in self.repo.lower():
                    if not (has_anchor or has_cargo or has_package_json):
                        self.red_flags.append("Claims to be Solana project but missing Anchor/Cargo/package.json")
                        self.score -= 20
        except:
            pass
    
    def check_license_and_docs(self):
        """Check for license and proper documentation"""
        has_license = self.repo_data.get("license") is not None
        
        if not has_license:
            self.red_flags.append("No license - unprofessional or incomplete project")
            self.score -= 10
    
    def get_risk_level(self) -> Tuple[str, str]:
        """Determine risk level based on score"""
        if self.score >= 80:
            return "LOW RISK", "✅"
        elif self.score >= 60:
            return "MEDIUM-LOW RISK", "⚠️"
        elif self.score >= 40:
            return "MEDIUM-HIGH RISK", "⚠️"
        elif self.score >= 20:
            return "HIGH RISK", "🚨"
        else:
            return "CRITICAL RISK", "🔴"
    
    def print_results(self):
        """Print formatted analysis results"""
        risk_level, emoji = self.get_risk_level()
        
        print("\n" + "="*70)
        print("🛡️  SOLANA REPOSITORY SECURITY ANALYSIS")
        print("="*70)
        print(f"\n📦 Repository: {self.owner}/{self.repo}")
        print(f"🔗 URL: https://github.com/{self.owner}/{self.repo}")
        print(f"\n{emoji} RISK SCORE: {self.score}/100 ({risk_level})")
        print("="*70)
        
        if self.red_flags:
            print(f"\n🚩 RED FLAGS DETECTED ({len(self.red_flags)}):\n")
            for i, flag in enumerate(self.red_flags, 1):
                print(f"  {i}. {flag}")
        else:
            print("\n✅ No major red flags detected - Project appears legitimate")
        
        print(f"\n{'='*70}")
        print("📊 REPOSITORY METADATA:")
        print(f"  • Stars: {self.repo_data.get('stargazers_count', 0)}")
        print(f"  • Forks: {self.repo_data.get('forks_count', 0)}")
        print(f"  • Watchers: {self.repo_data.get('watchers_count', 0)}")
        print(f"  • Open Issues: {self.repo_data.get('open_issues_count', 0)}")
        print(f"  • Commits: {len(self.commits)}")
        print(f"  • Language: {self.repo_data.get('language', 'Unknown')}")
        print(f"  • Created: {self.repo_data.get('created_at', 'Unknown')[:10]}")
        print(f"  • Last Updated: {self.repo_data.get('updated_at', 'Unknown')[:10]}")
        print(f"  • License: {self.repo_data.get('license', {}).get('name', 'None') if self.repo_data.get('license') else 'None'}")
        print(f"  • Is Fork: {'Yes' if self.repo_data.get('fork', False) else 'No'}")
        print("="*70 + "\n")
    
    def analyze(self) -> Dict:
        """Run complete analysis pipeline"""
        print(f"\n🔍 Analyzing repository: {self.repo_url}\n")
        
        if not self.parse_url():
            return {"error": "Invalid URL"}
        
        if not self.fetch_repo_data():
            return {"error": "Failed to fetch repository data"}
        
        self.fetch_commits()
        
        # Run all checks
        self.check_commit_patterns()
        self.check_community_engagement()
        self.check_code_to_commit_ratio()
        self.check_description_and_readme()
        self.check_solana_specific_indicators()
        self.check_license_and_docs()
        
        # Ensure score stays within bounds
        self.score = max(0, min(100, self.score))
        
        # Print results
        self.print_results()
        
        risk_level, _ = self.get_risk_level()
        
        return {
            "score": self.score,
            "risk_level": risk_level,
            "red_flags": self.red_flags,
            "metadata": {
                "stars": self.repo_data.get('stargazers_count', 0),
                "forks": self.repo_data.get('forks_count', 0),
                "commits": len(self.commits),
                "language": self.repo_data.get('language', 'Unknown')
            }
        }


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("\n🛡️  Solana Repository Security Scanner")
        print("="*70)
        print("\nUsage: python3 analyze.py <github_url>")
        print("\nExamples:")
        print("  python3 analyze.py https://github.com/solana-labs/solana")
        print("  python3 analyze.py https://github.com/coral-xyz/anchor")
        print("  python3 analyze.py https://github.com/Momo111psy/solguard-ai")
        print("\n" + "="*70 + "\n")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    scanner = SolanaRepoScanner(repo_url)
    result = scanner.analyze()
    
    if "error" in result:
        print(f"\n❌ Error: {result['error']}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
