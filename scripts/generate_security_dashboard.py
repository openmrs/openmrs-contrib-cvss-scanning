#!/usr/bin/env python3
"""
OpenMRS O3 Security Dashboard Generator
Parses test results and generates HTML dashboard with CVSS scores

CVSS 4.0 Migration: Automatically extracts test descriptions from docstrings
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

def get_test_description_from_docstring(test_nodeid):
    """
    Extract description from test function docstring.
    Falls back to manual mapping if docstring not found.
    """
    try:
        # Parse the nodeid
        if '::' not in test_nodeid:
            return get_test_description_fallback(test_nodeid)
        
        file_path, test_name = test_nodeid.split('::')
        
        # Convert relative path to absolute
        abs_path = Path(file_path).resolve()
        
        if not abs_path.exists():
            print(f"Warning: Test file not found: {abs_path}")
            return get_test_description_fallback(test_name)
        
        # Read the file directly and extract docstring
        with open(abs_path, 'r') as f:
            content = f.read()
        
        # Find the function definition and its docstring
        # Pattern: def test_name(): followed by """docstring"""
        pattern = rf'def {re.escape(test_name)}\([^)]*\):\s*"""(.*?)"""'
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            docstring = match.group(1).strip()
            # Clean up the docstring - join all lines
            lines = [line.strip() for line in docstring.split('\n') if line.strip()]
            description = ' '.join(lines)
            
            # Limit length for dashboard display
            if len(description) > 250:
                description = description[:247] + '...'
            
            return description
        else:
            print(f"Warning: No docstring found for {test_name}")
            return get_test_description_fallback(test_name)
        
    except Exception as e:
        print(f"Warning: Could not extract docstring for {test_nodeid}: {e}")
        return get_test_description_fallback(test_nodeid.split('::')[-1] if '::' in test_nodeid else test_nodeid)


def get_test_description_fallback(test_name):
    """
    Fallback manual mapping if docstring extraction fails.
    This ensures backwards compatibility.
    """
    # Manual mapping for existing tests
    descriptions = {
        'test_brute_force_password': 'Tests account lockout and cooldown after 7 failed login attempts with known username "admin". Uses CVSS 4.0 with dynamic scoring based on observed security mechanisms.',
        'test_credential_guessing': 'Complete credential guessing attack (random username + password)',
        'test_password_attack_6_attempts': 'Password attack with 6 incorrect attempts',
        'test_password_attack_7_attempts': 'Password attack with 7 incorrect attempts',
        'test_password_attack_8_attempts': 'Password attack with 8 incorrect attempts',
        'test_session_hijacking': 'Session hijacking attack using stolen session token',
        'test_idle_timeout': 'Idle session timeout verification',
        'test_expired_session_reuse': 'Expired session token reuse attempt',
    }
    
    # Try to match test name
    for key, desc in descriptions.items():
        if key in test_name:
            return desc
    
    # Last resort: make it readable from function name
    readable_name = test_name.replace('test_', '').replace('_', ' ').title()
    return f'{readable_name} security test'


def extract_cvss_score(log_content, test_name):
    """
    Extract CVSS score for a specific test from logs.
    Handles both CVSS 3.1 and CVSS 4.0 formats.
    
    Strategy:
    1. Try to find score near the test name
    2. If multiple tests ran, extract the right one
    3. Fallback to last score if only one test
    """
    # Clean test name for pattern matching
    clean_test_name = test_name.replace('test_', '').replace('_', ' ')
    
    # Try to find score in section related to this test
    # Look for test name followed by CVSS score within reasonable distance (2000 chars)
    test_section_pattern = rf'{re.escape(test_name)}.*?CVSS Base Score:\s*([\d.]+)'
    match = re.search(test_section_pattern, log_content, re.DOTALL)
    
    if match and len(match.group(0)) < 3000:  # Ensure we didn't match too far
        return float(match.group(1))
    
    # Fallback: If only one score in entire log, use it
    pattern = r'CVSS Base Score:\s*([\d.]+)'
    matches = re.findall(pattern, log_content)
    
    if matches:
        # If only one score found, must be the right one
        if len(matches) == 1:
            return float(matches[0])
        
        # Multiple scores - try to match by position in log
        # Find all test names and their positions
        test_positions = [(m.start(), test_name) for m in re.finditer(re.escape(test_name), log_content)]
        score_positions = [(m.start(), float(m.group(1))) for m in re.finditer(pattern, log_content)]
        
        # Find the score closest after this test name
        if test_positions and score_positions:
            test_pos = test_positions[0][0]
            for score_pos, score in score_positions:
                if score_pos > test_pos:
                    return score
        
        # Last resort: return last score
        return float(matches[-1])
    
    return None


def get_severity_level(cvss_score):
    """
    Determine severity level based on CVSS score.
    Same ranges for both CVSS 3.1 and 4.0.
    """
    if cvss_score is None:
        return 'UNKNOWN'
    
    if cvss_score >= 9.0:
        return 'CRITICAL'
    elif cvss_score >= 7.0:
        return 'HIGH'
    elif cvss_score >= 4.0:
        return 'MEDIUM'
    elif cvss_score > 0.0:
        return 'LOW'
    else:
        return 'NONE'


def get_severity_color(severity):
    """Return color code for severity level"""
    colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
        'NONE': '#6c757d',
        'UNKNOWN': '#6c757d',
    }
    return colors.get(severity, '#6c757d')


def parse_test_results():
    """Parse pytest JSON report and test output log"""
    
    # Load JSON report
    try:
        with open('report.json', 'r') as f:
            json_report = json.load(f)
    except FileNotFoundError:
        print("Error: report.json not found")
        sys.exit(1)
    
    # Load test output log
    try:
        with open('test_output.log', 'r') as f:
            log_content = f.read()
    except FileNotFoundError:
        print("Warning: test_output.log not found")
        log_content = ""
    
    # Extract test results
    results = []
    
    for test in json_report.get('tests', []):
        test_name = test.get('nodeid', 'Unknown Test')
        status = 'PASS' if test.get('outcome') == 'passed' else 'FAIL'
        
        # Extract duration correctly
        # pytest JSON report stores duration in 'call' phase
        duration = test.get('call', {}).get('duration', 0)
        
        # If call duration is 0, try summing all phases
        if duration == 0 or duration is None:
            setup_duration = test.get('setup', {}).get('duration', 0) or 0
            call_duration = test.get('call', {}).get('duration', 0) or 0
            teardown_duration = test.get('teardown', {}).get('duration', 0) or 0
            duration = setup_duration + call_duration + teardown_duration
        
        # Extract CVSS score from logs
        cvss_score = extract_cvss_score(log_content, test_name)
        severity = get_severity_level(cvss_score)
        
        # Get adaptive description from docstring
        description = get_test_description_from_docstring(test_name)
        
        results.append({
            'full_name': test_name,
            'name': test_name.split('::')[-1],
            'description': description,
            'status': status,
            'cvss_score': cvss_score,
            'severity': severity,
            'duration': duration,
        })
    
    return results, json_report.get('summary', {})


def generate_html_dashboard(results, summary):
    """Generate HTML dashboard with CVSS scores"""
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenMRS O3 Security Dashboard - CVSS 4.0 Migration</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        .header h1 {{
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 32px;
        }}
        
        .header p {{
            color: #718096;
            font-size: 14px;
        }}
        
        .migration-notice {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
        }}
        
        .migration-notice h3 {{
            color: #856404;
            margin-bottom: 5px;
            font-size: 16px;
        }}
        
        .migration-notice p {{
            color: #856404;
            font-size: 14px;
            margin: 0;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        .stat-card h3 {{
            color: #718096;
            font-size: 14px;
            margin-bottom: 8px;
            text-transform: uppercase;
            font-weight: 600;
        }}
        
        .stat-card p {{
            color: #2d3748;
            font-size: 32px;
            font-weight: bold;
        }}
        
        .test-results {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        
        .test-results h2 {{
            padding: 20px;
            background: #f7fafc;
            color: #2d3748;
            border-bottom: 1px solid #e2e8f0;
            font-size: 20px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead {{
            background: #f7fafc;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            color: #4a5568;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            border-bottom: 2px solid #e2e8f0;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #e2e8f0;
            color: #2d3748;
        }}
        
        tr:hover {{
            background: #f7fafc;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .status-pass {{
            background: #c6f6d5;
            color: #22543d;
        }}
        
        .status-fail {{
            background: #fed7d7;
            color: #742a2a;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }}
        
        .cvss-score {{
            font-weight: bold;
            font-size: 18px;
        }}
        
        .footer {{
            text-align: center;
            color: white;
            margin-top: 30px;
            font-size: 14px;
        }}
        
        .footer a {{
            color: white;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 OpenMRS O3 Security Dashboard</h1>
            <p>Continuous Security Testing with CVSS Vulnerability Scoring</p>
            <p style="margin-top: 5px; font-size: 12px;">Last Updated: {now}</p>
        </div>
        
        <div class="migration-notice">
            <h3>⚠️ CVSS 4.0 Migration - Phase 1</h3>
            <p>Currently migrating from CVSS 3.1 to CVSS 4.0. Only brute force test is using CVSS 4.0 scoring. Other tests will be updated in future phases.</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Tests</h3>
                <p>{summary.get('total', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Passed</h3>
                <p style="color: #38a169;">{summary.get('passed', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Failed</h3>
                <p style="color: #e53e3e;">{summary.get('failed', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Duration</h3>
                <p>{summary.get('duration', 0):.1f}s</p>
            </div>
        </div>
        
        <div class="test-results">
            <h2>Test Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Test Name</th>
                        <th>Description</th>
                        <th>Status</th>
                        <th>CVSS Score</th>
                        <th>Severity</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # Add test rows
    for r in results:
        status_class = 'status-pass' if r['status'] == 'PASS' else 'status-fail'
        severity_color = get_severity_color(r['severity'])
        
        cvss_display = f"{r['cvss_score']:.1f}" if r['cvss_score'] is not None else 'N/A'
        
        # Format duration nicely
        duration = r['duration']
        if duration >= 60:
            duration_display = f"{duration/60:.1f}m"
        else:
            duration_display = f"{duration:.2f}s"
        
        html += f"""
                    <tr>
                        <td><strong>{r['name']}</strong></td>
                        <td>{r['description']}</td>
                        <td><span class="status-badge {status_class}">{r['status']}</span></td>
                        <td><span class="cvss-score">{cvss_display}</span></td>
                        <td><span class="severity-badge" style="background-color: {severity_color};">{r['severity']}</span></td>
                        <td>{duration_display}</td>
                    </tr>
"""
    
    html += """
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>OpenMRS O3 Continuous Security Testing</p>
            <p>Powered by <a href="https://www.first.org/cvss/v4.0/" target="_blank">CVSS 4.0</a> | 
            <a href="https://github.com/openmrs/openmrs-contrib-cvss-scanning" target="_blank">GitHub Repository</a></p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


def main():
    """Main dashboard generation function"""
    print("="*70)
    print("OpenMRS O3 Security Dashboard Generator")
    print("="*70)
    print("")
    
    print("Parsing test results...")
    results, summary = parse_test_results()
    
    print(f"Found {len(results)} test(s)")
    for r in results:
        cvss_str = f"CVSS {r['cvss_score']:.1f}" if r['cvss_score'] else "No CVSS"
        duration_str = f"{r['duration']:.1f}s" if r['duration'] else "0s"
        print(f"  - {r['name']}: {r['status']} ({cvss_str}, {duration_str})")
        print(f"    Description: {r['description'][:80]}...")
    
    print("")
    print("Generating HTML dashboard...")
    html_content = generate_html_dashboard(results, summary)
    
    # Write dashboard
    with open('security_dashboard.html', 'w') as f:
        f.write(html_content)
    
    print("✓ Dashboard saved to security_dashboard.html")
    print("")
    print("="*70)


if __name__ == '__main__':
    main()