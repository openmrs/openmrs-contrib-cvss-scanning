#!/usr/bin/env python3
"""
OpenMRS O3 Security Dashboard Generator
Parses test results and generates HTML dashboard with CVSS scores

CVSS 4.0 Migration: Automatically extracts test descriptions from docstrings
"""

import json
import re
import sys
import sqlite3
import os
from datetime import datetime
from datetime import timezone, timedelta
from pathlib import Path

# ============================================================================
# SQLITE DATABASE FUNCTIONS
# ============================================================================

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'test_results.db')

def init_db():
    """Initialize SQLite database. Creates tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS baselines (
            test_name TEXT PRIMARY KEY,
            baseline_score REAL NOT NULL,
            recorded_at TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_name TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            status TEXT NOT NULL,
            run_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_test_result(test_name, cvss_score, status):
    """Save result. Sets baseline if first run for this test."""
    if cvss_score is None:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('SELECT baseline_score FROM baselines WHERE test_name = ?', (test_name,))
    if c.fetchone() is None:
        c.execute(
            'INSERT INTO baselines (test_name, baseline_score, recorded_at) VALUES (?, ?, ?)',
            (test_name, cvss_score, now)
        )
    c.execute(
        'INSERT INTO history (test_name, cvss_score, status, run_at) VALUES (?, ?, ?, ?)',
        (test_name, cvss_score, status, now)
    )
    conn.commit()
    conn.close()


def get_baseline(test_name):
    """Get baseline score for a test."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT baseline_score FROM baselines WHERE test_name = ?', (test_name,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        print(f'Warning: Could not get baseline for {test_name}: {e}')
        return None


def get_history(test_name, limit=20):
    """Get last N CVSS scores for trend line (chronological order)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            'SELECT cvss_score FROM history WHERE test_name = ? ORDER BY run_at DESC LIMIT ?',
            (test_name, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in reversed(rows)]
    except Exception as e:
        print(f'Warning: Could not get history for {test_name}: {e}')
        return []


def get_improvement_html(baseline, current, history):
    """
    Generate colored improvement indicator HTML with mouseover tooltip
    showing last 10 runs with score and delta from baseline.
    """
    if baseline is None or current is None:
        return '<span style="color: #a0aec0;">—</span>'

    improvement = round(baseline - current, 1)

    if improvement > 0:
        label = f'<span style="color: #28a745; font-weight: bold;">+{improvement:.1f} ↑</span>'
    elif improvement < 0:
        label = f'<span style="color: #dc3545; font-weight: bold;">{improvement:.1f} ↓</span>'
    else:
        label = '<span style="color: #718096;">0.0 —</span>'

    # Build tooltip rows from history (last 10, most recent first)
    recent = list(reversed(history[-10:] if len(history) >= 10 else history))

    rows = ""
    for i, score in enumerate(recent):
        run_number = len(history) - i
        delta = round(baseline - score, 1)
        if delta > 0:
            delta_str = f'<span style="color: #68d391;">+{delta:.1f} ↑</span>'
        elif delta < 0:
            delta_str = f'<span style="color: #fc8181;">{delta:.1f} ↓</span>'
        else:
            delta_str = '<span style="color: #a0aec0;">0.0 —</span>'
        marker = ' ◀' if i == 0 else ''
        rows += f"<tr><td>Run {run_number}{marker}</td><td>{score:.1f}</td><td>{delta_str}</td></tr>"

    tooltip = f"""<div class="tooltip-wrapper">{label}<div class="tooltip-content">
            <strong>Last {len(recent)} Runs (Baseline: {baseline:.1f})</strong>
            <table class="tooltip-table">
                <thead><tr><th>Run</th><th>Score</th><th>Delta</th></tr></thead>
                <tbody>{rows}</tbody>
            </table></div></div>"""

    return tooltip

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
    
    est = timezone(timedelta(hours=-5))
    now = datetime.now(est).strftime('%Y-%m-%d %H:%M:%S EST')
    
    # Calculate total duration from individual test durations
    total_duration_sec = sum(r['duration'] for r in results)
    total_duration_min = total_duration_sec / 60
    
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
        .tooltip-wrapper {{
            position: relative;
            display: inline-block;
            cursor: pointer;
        }}
        .tooltip-wrapper .tooltip-content {{
            visibility: hidden;
            opacity: 0;
            background-color: #2d3748;
            color: white;
            border-radius: 8px;
            padding: 10px 14px;
            position: absolute;
            z-index: 100;
            bottom: 130%;
            left: 50%;
            transform: translateX(-50%);
            width: 280px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            transition: opacity 0.2s;
            font-size: 12px;
        }}
        .tooltip-wrapper:hover .tooltip-content {{
            visibility: visible;
            opacity: 1;
        }}
        .tooltip-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 6px;
        }}
        .tooltip-table th {{
            color: #a0aec0;
            font-size: 11px;
            text-align: left;
            padding: 3px 4px;
            border-bottom: 1px solid #4a5568;
        }}
        .tooltip-table td {{
            padding: 3px 4px;
            font-size: 11px;
            color: white;
            border-bottom: 1px solid #3a4a5a;
        }}
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 OpenMRS O3 Security Dashboard</h1>
            <p>Continuous Security Testing with CVSS Vulnerability Scoring</p>
            <p style="margin-top: 5px; font-size: 12px;">Last Updated: {now}</p>
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
                <p>{total_duration_min:.1f}m</p>
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
                        <th>CVSS Score (Baseline)</th>
                        <th>Severity</th>
                        <th>Improvement</th>
                        <th>Trend</th>
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

        # Improvement column
        improvement_html = get_improvement_html(r.get('baseline'), r.get('cvss_score'), r.get('history', []))

        # Trend sparkline
        history = r.get('history', [])
        chart_id = f"chart_{r['name']}"
        history_json = json.dumps(history)
        labels_json = json.dumps([f"Run {i+1}" for i in range(len(history))])

        if len(history) >= 2:
            trend_html = f'''<canvas id="{chart_id}" width="120" height="40"></canvas>
                        <script>
                        new Chart(document.getElementById("{chart_id}"), {{
                            type: "line",
                            data: {{
                                labels: {labels_json},
                                datasets: [{{
                                    data: {history_json},
                                    borderColor: "#667eea",
                                    borderWidth: 2,
                                    pointRadius: 2,
                                    fill: false,
                                    tension: 0.3
                                }}]
                            }},
                            options: {{
                                plugins: {{ legend: {{ display: false }} }},
                                scales: {{
                                    x: {{ display: false }},
                                    y: {{ display: false, min: 0, max: 10 }}
                                }},
                                animation: false
                            }}
                        }});
                        </script>'''
        else:
            trend_html = '<span style="color: #a0aec0; font-size: 12px;">Not enough data</span>'

        html += f"""
                    <tr>
                        <td><strong>{r['name'].replace('test_', '').replace('_', ' ').title()}</strong></td>
                        <td>{r['description']}</td>
                        <td><span class="status-badge {status_class}">{r['status']}</span></td>
                        <td><span class="cvss-score">{cvss_display}</span></td>
                        <td><span class="severity-badge" style="background-color: {severity_color};">{r['severity']}</span></td>
                        <td>{improvement_html}</td>
                        <td>{trend_html}</td>
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
    
    print("Initializing database...")
    init_db()

    print("Parsing test results...")
    results, summary = parse_test_results()

    print(f"Found {len(results)} test(s)")
    for r in results:
        cvss_str = f"CVSS {r['cvss_score']:.1f}" if r['cvss_score'] else "No CVSS"
        duration_str = f"{r['duration']:.1f}s" if r['duration'] else "0s"
        print(f"  - {r['name']}: {r['status']} ({cvss_str}, {duration_str})")
        print(f"    Description: {r['description'][:80]}...")
        
        # Save to DB (sets baseline on first run)
        save_test_result(r['name'], r['cvss_score'], r['status'])

    # Enrich results with baseline, improvement, and history from DB
    for r in results:
        r['baseline'] = get_baseline(r['name'])
        r['history'] = get_history(r['name'])

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