import re
import json
from datetime import datetime
from zoneinfo import ZoneInfo

# Read test output log
try:
    with open('test_output.log', 'r') as f:
        output = f.read()
except:
    print("No test output found")
    output = ""

# Parse CVSS scores from output
# Looking for pattern: "CVSS Base Score: X.X"
cvss_pattern = r'CVSS Base Score: ([\d.]+)'
cvss_scores = re.findall(cvss_pattern, output)

print(f"Found {len(cvss_scores)} CVSS scores in output")

# Read pytest JSON report
results = []
try:
    with open('report.json', 'r') as f:
        data = json.load(f)

    # Combine test results with CVSS scores
    for i, test in enumerate(data.get('tests', [])):
        result = {
            'name': test['nodeid'].split('::')[-1],
            'full_name': test['nodeid'],
            'outcome': test['outcome'],
            'duration': test.get('call', {}).get('duration', 0),
            'cvss_score': float(cvss_scores[i]) if i < len(cvss_scores) else None
        }
        results.append(result)
except Exception as e:
    print(f"Error reading report.json: {e}")

# Save enhanced results
with open('security_results.json', 'w') as f:
    json.dump({
        'timestamp': datetime.now().isoformat(),
        'total_tests': len(results),
        'passed': sum(1 for r in results if r['outcome'] == 'passed'),
        'failed': sum(1 for r in results if r['outcome'] != 'passed'),
        'tests': results
    }, f, indent=2)

# Print summary to console
print("\n" + "="*70)
print("SECURITY TEST RESULTS WITH CVSS SCORES")
print("="*70)
for r in results:
    status = "✅ PASS" if r['outcome'] == 'passed' else "❌ FAIL"
    cvss = f"CVSS: {r['cvss_score']:.1f}" if r['cvss_score'] else "CVSS: N/A"
    print(f"{status} | {cvss:12} | {r['name']}")
print("="*70 + "\n")

# Generate HTML Security Dashboard
def get_cvss_severity(score):
    if score is None:
        return "unknown", "N/A"
    if score >= 9.0:
        return "critical", "CRITICAL"
    elif score >= 7.0:
        return "high", "HIGH"
    elif score >= 4.0:
        return "medium", "MEDIUM"
    else:
        return "low", "LOW"

html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>OpenMRS Security Test Results</title>
            <style>
                * {{ box-sizing: border-box; margin: 0; padding: 0; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 20px;
                    min-height: 100vh;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }}
                h1 {{
                    color: #2d3748;
                    margin-bottom: 10px;
                    font-size: 32px;
                }}
                .subtitle {{
                    color: #718096;
                    margin-bottom: 30px;
                    font-size: 16px;
                }}
                .timestamp {{
                    color: #a0aec0;
                    font-size: 14px;
                    margin-bottom: 30px;
                }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }}
                .stat-card {{
                    padding: 25px;
                    border-radius: 8px;
                    text-align: center;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .stat-card.passed {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }}
                .stat-card.failed {{
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                }}
                .stat-card.total {{
                    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                    color: white;
                }}
                .stat-card h3 {{
                    font-size: 14px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    opacity: 0.9;
                    margin-bottom: 10px;
                }}
                .stat-card .number {{
                    font-size: 48px;
                    font-weight: bold;
                    margin: 10px 0;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 30px 0;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    border-radius: 8px;
                    overflow: hidden;
                }}
                th {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    text-transform: uppercase;
                    font-size: 12px;
                    letter-spacing: 1px;
                }}
                td {{
                    padding: 15px;
                    border-bottom: 1px solid #e2e8f0;
                }}
                tr:hover {{
                    background: #f7fafc;
                }}
                tr:last-child td {{
                    border-bottom: none;
                }}
                .status-badge {{
                    display: inline-block;
                    padding: 6px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: 600;
                    text-transform: uppercase;
                }}
                .status-completed {{
                    background: #bee3f8;
                    color: #2c5282;
                }}
                .status-error {{
                    background: #fed7d7;
                    color: #742a2a;
                }}
                .cvss-score {{
                    font-weight: bold;
                    font-size: 16px;
                    color: #2d3748;
                }}
                .severity-badge {{
                    display: inline-block;
                    padding: 6px 12px;
                    border-radius: 6px;
                    font-weight: bold;
                    font-size: 12px;
                    text-transform: uppercase;
                }}
                .severity-critical {{ background: #c53030; color: white; }}
                .severity-high {{ background: #dd6b20; color: white; }}
                .severity-medium {{ background: #d69e2e; color: white; }}
                .severity-low {{ background: #38a169; color: white; }}
                .severity-unknown {{ background: #a0aec0; color: white; }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 2px solid #e2e8f0;
                    text-align: center;
                    color: #718096;
                }}
                .footer a {{
                    color: #667eea;
                    text-decoration: none;
                    font-weight: 600;
                }}
                .footer a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 OpenMRS O3 Security Testing</h1>
                <p class="subtitle">Automated BDD Security Tests with CVSS Vulnerability Scoring</p>
                <p class="timestamp">Last updated: {datetime.now(ZoneInfo('America/Indiana/Indianapolis')).strftime('%B %d, %Y at %I:%M %p EST')}</p>

                <div class="summary">
                    <div class="stat-card passed">
                        <h3>Completed</h3>
                        <div class="number">{sum(1 for r in results if r['outcome'] == 'passed')}</div>
                    </div>
                    <div class="stat-card failed">
                        <h3>Errors</h3>
                        <div class="number">{sum(1 for r in results if r['outcome'] != 'passed')}</div>
                    </div>
                    <div class="stat-card total">
                        <h3>Total Tests</h3>
                        <div class="number">{len(results)}</div>
                    </div>
                </div>

                <h2 style="margin: 40px 0 20px 0; color: #2d3748;">Security Test Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Test Name</th>
                            <th>Test Execution</th>
                            <th>CVSS Score</th>
                            <th>Severity</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>
        """

for r in results:
    # Status badge - CHANGED: "Completed" / "Error"
    status_class = "status-completed" if r['outcome'] == 'passed' else "status-error"
    status_text = "Completed" if r['outcome'] == 'passed' else "Error"

    # CVSS score and severity - SPLIT INTO TWO COLUMNS
    cvss = r.get('cvss_score')
    severity_class, severity_text = get_cvss_severity(cvss)

    if cvss:
        cvss_display = f'<span class="cvss-score">{cvss:.1f}</span>'
        severity_display = f'<span class="severity-badge severity-{severity_class}">{severity_text}</span>'
    else:
        cvss_display = '<span class="cvss-score">N/A</span>'
        severity_display = '<span class="severity-badge severity-unknown">N/A</span>'

    # Clean test name
    test_name = r['name'].replace('_', ' ').replace('test ', '').title()

    html += f"""
                        <tr>
                            <td><strong>{test_name}</strong></td>
                            <td><span class="status-badge {status_class}">{status_text}</span></td>
                            <td>{cvss_display}</td>
                            <td>{severity_display}</td>
                            <td>{r['duration']:.2f}s</td>
                        </tr>
            """

html += f"""
                    </tbody>
                </table>

                <div class="footer">
                    <p><a href="report.html">📊 View Detailed pytest Report</a> |
                    <a href="security_results.json">📄 Download JSON Data</a></p>
                    <p style="margin-top: 10px; font-size: 12px;">
                        OpenMRS Continuous Security Testing | NSF-Funded Research
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

with open('security_dashboard.html', 'w') as f:
    f.write(html)

print("✅ Security dashboard generated: security_dashboard.html")
