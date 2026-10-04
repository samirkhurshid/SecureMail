"""
Unified Test Runner for SecureMail
Runs both the backend regression test suite and the synthetic malicious email suite.
"""
import os
import sys
import subprocess

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "Backend")
TEST_SUITE_DIR = os.path.join(BASE_DIR, "Test_Suite")

def main():
    print("=" * 80)
    print("  SECUREMAIL UNIFIED TEST VERIFICATION RUNNER")
    print("=" * 80)
    
    print("\n[1/2] Running Backend Pytest Regression Suite (128 tests)...")
    res1 = subprocess.run([sys.executable, "-m", "pytest", "tests/"], cwd=BACKEND_DIR)
    
    print("\n[2/2] Running Malicious & Clean EML Sample Verification Suite...")
    res2 = subprocess.run([sys.executable, "run_tests.py"], cwd=TEST_SUITE_DIR)
    
    print("\n" + "=" * 80)
    if res1.returncode == 0 and res2.returncode == 0:
        print("  🎉 ALL TESTS PASSED SUCCESSFULLY! SYSTEM IS FULLY OPERATIONAL.")
    else:
        print("  ⚠️ ONE OR MORE TEST SUITES ENCOUNTERED AN ISSUE.")
    print("=" * 80)
    sys.exit(max(res1.returncode, res2.returncode))

if __name__ == "__main__":
    main()
