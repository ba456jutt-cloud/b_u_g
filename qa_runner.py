import os
import json
import unittest
import coverage
from datetime import datetime

def run_all_qa():
    print("=========================================")
    print("       Bug Bounty Copilot QA Runner      ")
    print("=========================================")
    
    # Start coverage
    cov = coverage.Coverage(source=['agents', 'core', 'tools', 'workflows', 'router', 'api'])
    cov.start()

    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    cov.stop()
    cov.save()
    
    # Calculate coverage percentage
    coverage_percent = cov.report(show_missing=False)
    
    # Generate structured JSON report
    qa_report = {
        "timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "failed": len(result.failures) + len(result.errors),
        "coverage": f"{coverage_percent:.2f}%",
        "critical_issues": [f[1] for f in result.failures] + [e[1] for e in result.errors],
        "recommendations": []
    }
    
    # If there are failures, we would typically trigger the ValidationAgent here
    if qa_report["failed"] > 0:
        qa_report["recommendations"].append("Trigger ValidationAgent to analyze stack traces.")
    else:
        qa_report["recommendations"].append("All systems operational. No action needed.")
        
    # Save Report
    os.makedirs("logs", exist_ok=True)
    report_path = "logs/qa_report.json"
    with open(report_path, "w") as f:
        json.dump(qa_report, f, indent=2)
        
    print("\n=========================================")
    print(f" QA Report generated at: {report_path}")
    print(f" Tests Run: {qa_report['tests_run']} | Passed: {qa_report['passed']} | Failed: {qa_report['failed']}")
    print(f" Code Coverage: {qa_report['coverage']}")
    print("=========================================")

if __name__ == "__main__":
    run_all_qa()
