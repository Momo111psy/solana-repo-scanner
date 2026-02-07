#!/usr/bin/env python3
"""
GitHub Red Flag Analyzer
Simple tool that analyzes a GitHub repo and outputs risk score + red flags
"""

import requests
import re
import sys


def analyze_repo(repo_url):
    """Analyze GitHub repository for red flags"""
    
    # Parse URL
    match = re.search(r"github\.com/([^/]+)/([^/]+)", repo_url)
    if not match:
        return {"error": "Invalid GitHub URL"}
    
    owner, repo = match.group(1), match.group(2).replace(".git", "")
    
    print(f"\n🔍 Analyzing: {owner}/{repo}\n")
    
    # Fetch repo data
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(api_url)
    
    if response.status_code != 200:
        return {"error": f"Failed to fetch repo (Status: {response.status_code})"}
    
    repo_data = response.json()
    
    # Fetch commits
    commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    commits_response = requests.get(commits_url)
    commits = commits_response.json() if commits_response.status_code == 200 else []
    
    # Initialize
    red_flags = []
    score = 100
    
    # Check 1: Commit count
    commit_count = len(commits)
    if commit_count < 5:
        red_flags.append(f"Only {commit_count} commits - suspiciously low")
        score -= 30
    elif commit_count < 20:
        red_flags.append(f"{commit_count} commits - below average")
        score -= 15
    
    # Check 2: Stars and forks
    stars = repo_data.get("stargazers_count", 0)
    forks = repo_data.get("forks_count", 0)
    
    if stars == 0:
        red_flags.append("0 stars - no community interest")
        score -= 20
    
    if forks == 0:
        red_flags.append("0 forks - no community contribution")
        score -= 15
    
    # Check 3: Description marketing language
    description = repo_data.get("description", "").lower()
    marketing_terms = ["world's first", "revolutionary", "80%", "game-changing", "unprecedented"]
    if any(term in description for term in marketing_terms):
        red_flags.append("Marketing language detected in description")
        score -= 15
    
    # Check 4: Check README for funding language
    readme_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md"
    try:
        readme_response = requests.get(readme_url, timeout=5)
        if readme_response.status_code == 200:
            readme = readme_response.text.lower()
            funding_keywords = ["seeking", "grant", "subsidy", "funding"]
            funding_count = sum(keyword in readme for keyword in funding_keywords)
            if funding_count >= 2:
                red_flags.append("Funding-seeking language detected in README")
                score -= 15
    except:
        pass
    
    # Check 5: Lines of code vs commits
    try:
        lang_url = f"https://api.github.com/repos/{owner}/{repo}/languages"
        lang_response = requests.get(lang_url, timeout=5)
        if lang_response.status_code == 200:
            total_loc = sum(lang_response.json().values())
            if total_loc > 1000 and commit_count < 5:
                red_flags.append(f"Only {commit_count} commits for {total_loc:,} lines of code")
                score -= 20
    except:
        pass
    
    # Ensure score doesn't go negative
    score = max(0, score)
    
    # Determine risk level
    if score >= 70:
        risk_level = "✅ LOW RISK"
    elif score >= 40:
        risk_level = "⚠️  MEDIUM RISK"
    else:
        risk_level = "🚨 HIGH RISK"
    
    # Print results
    print(f"{'='*60}")
    print(f"RISK SCORE: {score}/100 ({risk_level})")
    print(f"{'='*60}\n")
    
    if red_flags:
        print("🚩 RED FLAGS DETECTED:\n")
        for flag in red_flags:
            print(f"  • {flag}")
    else:
        print("✅ No major red flags detected")
    
    print(f"\n{'='*60}")
    print(f"METADATA:")
    print(f"  • Stars: {stars}")
    print(f"  • Forks: {forks}")
    print(f"  • Commits: {commit_count}")
    print(f"  • Language: {repo_data.get('language', 'Unknown')}")
    print(f"  • Created: {repo_data.get('created_at', 'Unknown')[:10]}")
    print(f"{'='*60}\n")
    
    return {
        "score": score,
        "risk_level": risk_level,
        "red_flags": red_flags,
        "stars": stars,
        "forks": forks,
        "commits": commit_count
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 github_analyzer.py <github_url>")
        print("Example: python3 github_analyzer.py https://github.com/Momo111psy/solguard-ai")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    result = analyze_repo(repo_url)
    
    if "error" in result:
        print(f"\n❌ Error: {result['error']}\n")
        sys.exit(1)
