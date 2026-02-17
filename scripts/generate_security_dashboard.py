#!/usr/bin/env python3
"""
OpenMRS O3 Security Dashboard Generator
Parses test results and generates HTML dashboard with CVSS scores

CVSS 4.0 Migration: Automatically extracts test descriptions from docstrings
Phase 2: Added historical tracking with SQLite database
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path
import inspect
import importlib.util

# Import database module for historical tracking
from database import SecurityTestDatabase


def get_test_description_from_docstring(test_nodeid):
    """
    Extract description from test function docstring.
    Falls back to manual mapping if docstring not found.
    
    This makes the dashboard adaptive - contributors can add new tests
    without modifying the dashboard code. Just add a docstring!
    
    Example nodeid: 'tests/authentication/test_01_brute_force_password.py::test_brute_force_password'
    
    Args:
        test_nodeid: Full pytest node ID (filepath::function_name)
        
    Returns:
        String description of the test
    """
    try:
        # Parse the nodeid to get file path and test function name
        if '::' not in test_nodeid:
            return get_test_description_fallback(test_nodeid)
        
        file_path, test_name = test_nodeid.split('::')
        
        # Convert relative path to absolute
        abs_path = Path(file_path).resolve()
        
        if not abs_path.exists():
            print(f"Warning: Test file not found: {abs_path}")
            return get_test_description_fallback(test_name)
        
        # Load the test module dynamically
        spec = importlib.util.spec_from_file_location("test_module", abs_path)
        if spec is None or spec.loader is None:
            print(f"Warning: Could not load module spec for {abs_path}")
            return get_test_description_fallback(test_name)
        
        module = importlib.util.module_from_spec(spec)
        sys.modules['test_module'] = module
        spec.loader.exec_module(module)
        
        # Get the test function
        test_func = getattr(module, test_name, None)
        
        if test_func and test_func.__doc__:
            # Clean up the docstring
            docstring = inspect.cleandoc(test_func.__doc__)
            
            # Return first paragraph (before first blank line)
            first_paragraph = docstring.split('\n\n')[0]
            
            # Join lines and clean up whitespace
            description = ' '.join(first_paragraph.split('\n')).strip()
            
            # Limit length for dashboard display
            if len(description) > 200:
                description = description[:197] + '...'
            
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
        'test_brute_force_password': 'Brute force password attack with known admin username',
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
        duration = test.get('duration', 0)
        
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


def get_historical_data():
    """Get baseline and historical data from database"""
    try:
        db = SecurityTestDatabase('../test_results.db')
        all_scores = db.get_all_current_scores()
        
        # Get history for trend charts (last 20 runs)
        test_histories = {}
        for score_data in all_scores:
            test_name = score_data['test_name']
            history = db.get_test_history(test_name, limit=20)
            test_histories[test_name] = history
        
        db.close()
        
        # Convert to lookup dictionary by test name
        baselines = {item['test_name']: item for item in all_scores}
        return baselines, test_histories
    except Exception as e:
        print(f"Warning: Could not load historical data: {e}")
        return {}, {}


def get_improvement_indicator(relative_score):
    """Generate improvement indicator HTML"""
    if relative_score > 0:
        return f'<span style="color: #28a745; font-weight: bold;">+{relative_score:.1f} ↗️</span>'
    elif relative_score < 0:
        return f'<span style="color: #dc3545; font-weight: bold;">{relative_score:.1f} ↘️</span>'
    else:
        return '<span style="color: #6c757d;">0.0 ━━</span>'


def generate_html_dashboard(results, summary, baselines, test_histories):
    """Generate HTML dashboard with CVSS scores and historical tracking"""
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenMRS O3 Security Dashboard - CVSS 4.0</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
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
            max-width: 1400px;
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
            background: #bee3f8;
            border-left: 4px solid #3182ce;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
        }}
        
        .migration-notice h3 {{
            color: #2c5282;
            margin-bottom: 5px;
            font-size: 16px;
        }}
        
        .migration-notice p {{
            color: #2c5282;
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
            font-size: 16px;
        }}
        
        .trend-chart {{
            height: 60px;
            width: 150px;
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
            <h3>📊 Historical Tracking Enabled</h3>
            <p>This dashboard now tracks CVSS score changes over time. Baseline scores are compared against current runs to show security improvements (green ↗️) or regressions (red ↘️).</p>
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
                        <th style="width: 12%;">Test Name</th>
                        <th style="width: 22%;">Description</th>
                        <th style="width: 8%;">Status</th>
                        <th style="width: 8%;">Baseline</th>
                        <th style="width: 8%;">Current</th>
                        <th style="width: 10%;">Improvement</th>
                        <th style="width: 8%;">Duration</th>
                        <th style="width: 14%;">Trend</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # Add test rows with historical data
    for r in results:
        status_class = 'status-pass' if r['status'] == 'PASS' else 'status-fail'
        severity_color = get_severity_color(r['severity'])
        cvss_display = f"{r['cvss_score']:.1f}" if r['cvss_score'] is not None else 'N/A'
        
        # Get baseline data
        test_name = r['name']
        baseline_data = baselines.get(test_name, {})
        baseline_score = baseline_data.get('baseline_score', r['cvss_score'])
        relative_score = baseline_data.get('relative_score', 0.0)
        
        # Baseline display
        if baseline_score:
            baseline_severity = get_severity_level(baseline_score)
            baseline_color = get_severity_color(baseline_severity)
            baseline_html = f"""<div class="cvss-score">{baseline_score:.1f}</div>
                <span class="severity-badge" style="background-color: {baseline_color};">{baseline_severity}</span>"""
        else:
            baseline_html = '<span style="color: #a0aec0;">N/A</span>'
        
        # Current score display
        current_html = f"""<div class="cvss-score">{cvss_display}</div>
            <span class="severity-badge" style="background-color: {severity_color};">{r['severity']}</span>"""
        
        # Improvement indicator
        improvement_html = get_improvement_indicator(relative_score)
        
        # Chart data
        history = test_histories.get(test_name, [])
        chart_labels = [h['run_date'][:10] for h in reversed(history)]
        chart_scores = [h['cvss_score'] for h in reversed(history)]
        chart_id = f"chart-{test_name.replace('_', '-')}"
        
        html += f"""
                    <tr>
                        <td><strong>{r['name']}</strong></td>
                        <td>{r['description'][:120]}{'...' if len(r['description']) > 120 else ''}</td>
                        <td><span class="status-badge {status_class}">{r['status']}</span></td>
                        <td>{baseline_html}</td>
                        <td>{current_html}</td>
                        <td>{improvement_html}</td>
                        <td>{r['duration']:.2f}s</td>
                        <td><canvas id="{chart_id}" class="trend-chart"></canvas></td>
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
    
    <script>
        // Chart.js configuration
        const chartConfig = {
            type: 'line',
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return 'CVSS: ' + context.parsed.y.toFixed(1);
                            }
                        }
                    }
                },
                scales: {
                    x: { display: false },
                    y: {
                        min: 0,
                        max: 10,
                        ticks: { stepSize: 2 }
                    }
                }
            }
        };
"""
    
    # Generate charts
    for r in results:
        test_name = r['name']
        history = test_histories.get(test_name, [])
        chart_labels = [h['run_date'][:10] for h in reversed(history)]
        chart_scores = [h['cvss_score'] for h in reversed(history)]
        chart_id = f"chart-{test_name.replace('_', '-')}"
        
        html += f"""
        new Chart(document.getElementById('{chart_id}'), {{
            ...chartConfig,
            data: {{
                labels: {json.dumps(chart_labels)},
                datasets: [{{
                    data: {json.dumps(chart_scores)},
                    borderColor: 'rgb(102, 126, 234)',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 4
                }}]
            }}
        }});
"""
    
    html += """
    </script>
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
        print(f"  - {r['name']}: {r['status']} ({cvss_str})")
    
    print("")
    print("Loading historical data from database...")
    baselines, test_histories = get_historical_data()
    print(f"Loaded {len(baselines)} baseline(s)")
    
    print("")
    print("Generating HTML dashboard...")
    html_content = generate_html_dashboard(results, summary, baselines, test_histories)
    
    # Write dashboard
    with open('security_dashboard.html', 'w') as f:
        f.write(html_content)
    
    print("✓ Dashboard saved to security_dashboard.html")
    print("")
    print("="*70)


if __name__ == '__main__':
    main()
