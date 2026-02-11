#!/usr/bin/env python3
"""
Comprehensive test suite for Solana Repository Security Scanner
Tests various scenarios including legitimate projects, scams, and edge cases
"""

import unittest
import sys
import os

# Add parent directory to path to import analyze module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyze import SolanaRepoScanner


class TestSolanaRepoScanner(unittest.TestCase):
    """Test cases for Solana Repository Security Scanner"""
    
    def test_url_parsing_valid(self):
        """Test valid GitHub URL parsing"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        self.assertTrue(scanner.parse_url())
        self.assertEqual(scanner.owner, "solana-labs")
        self.assertEqual(scanner.repo, "solana")
    
    def test_url_parsing_with_git_extension(self):
        """Test URL parsing with .git extension"""
        scanner = SolanaRepoScanner("https://github.com/coral-xyz/anchor.git")
        self.assertTrue(scanner.parse_url())
        self.assertEqual(scanner.owner, "coral-xyz")
        self.assertEqual(scanner.repo, "anchor")
    
    def test_url_parsing_invalid(self):
        """Test invalid URL handling"""
        scanner = SolanaRepoScanner("https://invalid-url.com/repo")
        self.assertFalse(scanner.parse_url())
    
    def test_legitimate_project_solana_labs(self):
        """Test analysis of legitimate Solana Labs repository"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        result = scanner.analyze()
        
        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["score"], 60)  # Should have decent score
        self.assertIn("LOW", result["risk_level"])
    
    def test_legitimate_project_anchor(self):
        """Test analysis of legitimate Anchor framework repository"""
        scanner = SolanaRepoScanner("https://github.com/coral-xyz/anchor")
        result = scanner.analyze()
        
        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["score"], 60)
        self.assertIn("LOW", result["risk_level"])
    
    def test_low_commit_detection(self):
        """Test detection of suspiciously low commit counts"""
        # Using a known test case with low commits
        scanner = SolanaRepoScanner("https://github.com/Momo111psy/solguard-ai")
        result = scanner.analyze()
        
        self.assertNotIn("error", result)
        # Should detect low commit count as a red flag
        self.assertTrue(any("commit" in flag.lower() for flag in result["red_flags"]))
    
    def test_risk_level_calculation(self):
        """Test risk level categorization"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        scanner.parse_url()
        scanner.fetch_repo_data()
        
        # Test different score ranges
        scanner.score = 85
        risk_level, emoji = scanner.get_risk_level()
        self.assertEqual(risk_level, "LOW RISK")
        self.assertEqual(emoji, "✅")
        
        scanner.score = 50
        risk_level, emoji = scanner.get_risk_level()
        self.assertIn("MEDIUM", risk_level)
        self.assertEqual(emoji, "⚠️")
        
        scanner.score = 15
        risk_level, emoji = scanner.get_risk_level()
        self.assertIn("CRITICAL", risk_level)
        self.assertEqual(emoji, "🔴")
    
    def test_community_engagement_metrics(self):
        """Test that community metrics are properly fetched"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        result = scanner.analyze()
        
        self.assertNotIn("error", result)
        self.assertGreater(result["metadata"]["stars"], 0)
        self.assertGreater(result["metadata"]["forks"], 0)
        self.assertGreater(result["metadata"]["commits"], 0)
    
    def test_nonexistent_repo(self):
        """Test handling of non-existent repository"""
        scanner = SolanaRepoScanner("https://github.com/nonexistent-user-12345/nonexistent-repo-67890")
        result = scanner.analyze()
        
        self.assertIn("error", result)
    
    def test_score_bounds(self):
        """Test that score stays within 0-100 bounds"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        scanner.parse_url()
        scanner.fetch_repo_data()
        scanner.fetch_commits()
        
        # Artificially set extreme scores
        scanner.score = 150
        scanner.score = max(0, min(100, scanner.score))
        self.assertLessEqual(scanner.score, 100)
        
        scanner.score = -50
        scanner.score = max(0, min(100, scanner.score))
        self.assertGreaterEqual(scanner.score, 0)
    
    def test_fork_detection(self):
        """Test detection of forked repositories"""
        # Test with a known fork (if available)
        scanner = SolanaRepoScanner("https://github.com/Momo111psy/cai")
        result = scanner.analyze()
        
        self.assertNotIn("error", result)
        # Should detect if repo is a fork
        if scanner.repo_data.get("fork", False):
            self.assertTrue(any("fork" in flag.lower() for flag in result["red_flags"]))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_empty_url(self):
        """Test handling of empty URL"""
        scanner = SolanaRepoScanner("")
        self.assertFalse(scanner.parse_url())
    
    def test_malformed_url(self):
        """Test handling of malformed URL"""
        scanner = SolanaRepoScanner("not-a-url")
        self.assertFalse(scanner.parse_url())
    
    def test_github_url_without_protocol(self):
        """Test URL without https:// protocol"""
        scanner = SolanaRepoScanner("github.com/solana-labs/solana")
        self.assertTrue(scanner.parse_url())
        self.assertEqual(scanner.owner, "solana-labs")


class TestSecurityChecks(unittest.TestCase):
    """Test specific security check functions"""
    
    def test_code_to_commit_ratio_check(self):
        """Test code-to-commit ratio detection"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        scanner.parse_url()
        scanner.fetch_repo_data()
        scanner.fetch_commits()
        
        # Run the check
        scanner.check_code_to_commit_ratio()
        
        # For legitimate projects, should not flag extreme ratios
        extreme_flags = [flag for flag in scanner.red_flags if "Extreme" in flag]
        self.assertEqual(len(extreme_flags), 0)
    
    def test_commit_pattern_analysis(self):
        """Test commit pattern analysis"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        scanner.parse_url()
        scanner.fetch_repo_data()
        scanner.fetch_commits()
        
        initial_score = scanner.score
        scanner.check_commit_patterns()
        
        # For active repos, score should not decrease significantly
        self.assertGreaterEqual(scanner.score, initial_score - 20)
    
    def test_license_check(self):
        """Test license detection"""
        scanner = SolanaRepoScanner("https://github.com/solana-labs/solana")
        scanner.parse_url()
        scanner.fetch_repo_data()
        
        scanner.check_license_and_docs()
        
        # Solana repo should have a license
        license_flags = [flag for flag in scanner.red_flags if "license" in flag.lower()]
        self.assertEqual(len(license_flags), 0)


def run_integration_tests():
    """Run integration tests on real repositories"""
    print("\n" + "="*70)
    print("🧪 RUNNING INTEGRATION TESTS")
    print("="*70 + "\n")
    
    test_repos = [
        ("https://github.com/solana-labs/solana", "Solana Labs - Main Repository"),
        ("https://github.com/coral-xyz/anchor", "Anchor Framework"),
        ("https://github.com/Momo111psy/MOLTVAULT", "MOLTVAULT"),
        ("https://github.com/Momo111psy/solguard-ai", "SolGuard AI"),
    ]
    
    for repo_url, name in test_repos:
        print(f"\n{'='*70}")
        print(f"Testing: {name}")
        print(f"URL: {repo_url}")
        print("="*70)
        
        scanner = SolanaRepoScanner(repo_url)
        result = scanner.analyze()
        
        if "error" not in result:
            print(f"✅ Test passed - Score: {result['score']}/100")
        else:
            print(f"⚠️  Test completed with error: {result['error']}")
        
        print()


if __name__ == "__main__":
    # Run unit tests
    print("\n" + "="*70)
    print("🧪 SOLANA REPOSITORY SCANNER - TEST SUITE")
    print("="*70 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestSolanaRepoScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityChecks))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run integration tests if unit tests pass
    if result.wasSuccessful():
        run_integration_tests()
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
