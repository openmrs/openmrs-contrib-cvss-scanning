"""
Security Dashboard Generator with CVSS 4.0 Historical Tracking

Generates an interactive HTML dashboard showing:
- Current CVSS scores vs baseline
- Improvement/regression tracking (baseline - current)
- Inline trend charts using Chart.js
- Adaptive test descriptions from docstrings
"""

import re
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Import database module
sys.path.insert(0, os.path.dirname(__file__))
from database import SecurityTestDatabase


def get_test_description_from_docstring(test_nodeid: str) -> str:
    """
    Extract test description from the test function's docstring.
    
    This allows contributors to add tests without modifying dashboard code!
    The dashboard automatically reads the docstring.
    
    Args:
        test_nodeid: pytest node ID (e.g., "tests/authentication/test_01_brute_force_password.py::test_brute_force_password_attack")
    
    Returns:
        First line of docstring, or fallback description
    """
    # Extract file path and function name
    match = re.match(r'([^:]+)::(\w+)', test_nodeid)
    if not match:
        return "Security test"
    
    test_file_path, function_name = match.groups()
    
    # Check if file exists
    if not os.path.exists(test_file_path):
        # Try relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        test_file_path = os.path.join(script_dir, '..', test_file_path)
    
    if not os.path.exists(test_file_path):
        return "Security test"
    
    try:
        with open(test_file_path, 'r') as f:
            content = f.read()
        
        # Find function definition and its docstring
        pattern = rf'def {function_name}\s*\([^)]*\):\s*(?:"""([^"]+)"""|\'\'\'([^\']+)\'\'\')'
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            docstring = match.group(1) or match.group(2)
            # Get first non-empty line
            first_line = next((line.strip() for line in docstring.split('\n') if line.strip()), '')
            return first_line if first_line else "Security test"
    
    except Exception as e:
        print(f"Warning: Could not extract docstring from {test_file_path}: {e}")
    
    # Fallback to manual mapping
    fallback_descriptions = {
        'test_brute_force_password': 'Tests account lockout mechanism against brute force password attacks',
        'test_credential_guessing': 'Tests credential guessing with random usernames and passwords',
        'test_username_enumeration': 'Tests if system reveals valid usernames through error messages',
    }
    
    return fallback_descriptions.get(function_name, 'Security test')


def get_severity_label(cvss_score: float) -> str:
    """
    Get CVSS 4.0 severity rating label.
    
    CVSS 4.0 severity ratings:
    - None: 0.0
    - Low: 0.1 - 3.9
    - Medium: 4.0 - 6.9
    - High: 7.0 - 8.9
    - Critical: 9.0 - 10.0
    """
    if cvss_score == 0.0:
        return "NONE"
    elif cvss_score < 4.0:
        return "LOW"
    elif cvss_score < 7.0:
        return "MEDIUM"
    elif cvss_score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"


def get_severity_color(cvss_score: float) -> str:
    """Get color for severity label."""
    if cvss_score == 0.0:
        return "#28a745"  # Green
    elif cvss_score < 4.0:
        return "#ffc107"  # Yellow
    elif cvss_score < 7.0:
        return "#fd7e14"  # Orange
    elif cvss_score < 9.0:
        return "#dc3545"  # Red
    else:
        return "#6f42c1"  # Purple (Critical)


def get_improvement_indicator(relative_score: float) -> str:
    """
    Generate visual indicator for improvement/regression.
    
    Args:
        relative_score: baseline_score - current_score
            Positive = improvement (score decreased)
            Negative = regression (score increased)
    
    Returns:
        HTML string with colored indicator
    """
    if relative_score > 0:
        # Improvement - green with up arrow
        return f'<span style="color: #28a745; font-weight: bold;">+{relative_score:.1f} ↗️</span>'
    elif relative_score < 0:
        # Regression - red with down arrow
        return f'<span style="color: #dc3545; font-weight: bold;">{relative_score:.1f} ↘️</span>'
    else:
        # No change - gray
        return '<span style="color: #6c757d;">0.0 ━━</span>'


def generate_dashboard():
    """
    Generate HTML security dashboard with CVSS 4.0 historical tracking.
    
    Reads from SQLite database and generates interactive dashboard with:
    - Baseline vs current CVSS scores
    - Improvement/regression tracking
    - Chart.js trend visualization
    """
    
    # Initialize database
    db = SecurityTestDatabase()
    
    # Get all current test scores with baselines
    all_scores = db.get_all_current_scores()
    
    # Get history for trend charts (last 20 runs per test)
    test_histories = {}
    for score_data in all_scores:
        test_name = score_data['test_name']
        history = db.get_test_history(test_name, limit=20)
        test_histories[test_name] = history
    
    db.close()
    
    # Get current timestamp (EST)
    now = datetime.now()
    timestamp_est = now.strftime("%Y-%m-%d %I:%M:%S %p EST")
    
    # Build HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenMRS O3 Security Dashboard - CVSS 4.0</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        body {{
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }}
        .severity-badge {{
            padding: 0.3rem 0.6rem;
            border-radius: 0.25rem;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .test-card {{
            background: white;
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .cvss-score {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .trend-chart {{
            height: 80px;
        }}
        table {{
            background: white;
        }}
        th {{
            background-color: #667eea;
            color: white;
            font-weight: 600;
        }}
        .footer {{
            margin-top: 3rem;
            padding: 2rem 0;
            background-color: #343a40;
            color: white;
            text-align: center;
        }}
        .improvement-positive {{
            color: #28a745;
            font-weight: bold;
        }}
        .improvement-negative {{
            color: #dc3545;
            font-weight: bold;
        }}
        .improvement-neutral {{
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🔒 OpenMRS O3 Security Dashboard</h1>
            <p class="lead mb-0">CVSS 4.0 Vulnerability Assessment with Historical Tracking</p>
            <small>Last Updated: {timestamp_est}</small>
        </div>
    </div>
    
    <div class="container">
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="alert alert-info">
                    <strong>📊 Historical Tracking Enabled!</strong> This dashboard now tracks CVSS score changes over time.
                    Baseline scores are compared against current runs to show security improvements (green ↗️) or regressions (red ↘️).
                </div>
            </div>
        </div>
"""
    
    if not all_scores:
        html_content += """
        <div class="alert alert-warning">
            <h4>No Test Results Available</h4>
            <p>No security tests have been run yet. The database will be populated on the first test run.</p>
        </div>
"""
    else:
        # Table header
        html_content += """
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th style="width: 20%;">Test Name</th>
                        <th style="width: 25%;">Description</th>
                        <th style="width: 10%;">Status</th>
                        <th style="width: 10%;">Baseline</th>
                        <th style="width: 10%;">Current</th>
                        <th style="width: 10%;">Improvement</th>
                        <th style="width: 15%;">Trend (Last 20 Runs)</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        # Generate rows for each test
        for idx, score_data in enumerate(all_scores):
            test_name = score_data['test_name']
            baseline_score = score_data['baseline_score']
            current_score = score_data.get('current_score', baseline_score)
            relative_score = score_data['relative_score']
            status = score_data['status']
            
            # Get description from test file
            # Reconstruct test_nodeid (we'll need to store this in database in future, for now use naming convention)
            test_nodeid = f"tests/authentication/{test_name}.py::{test_name}_attack"
            description = get_test_description_from_docstring(test_nodeid)
            
            # Severity labels
            baseline_severity = get_severity_label(baseline_score)
            baseline_color = get_severity_color(baseline_score)
            
            current_severity = get_severity_label(current_score)
            current_color = get_severity_color(current_score)
            
            # Status icon
            status_icon = "✓" if status == "PASS" else "✗"
            status_class = "text-success" if status == "PASS" else "text-danger"
            
            # Improvement indicator
            improvement_html = get_improvement_indicator(relative_score)
            
            # Chart data for this test
            history = test_histories.get(test_name, [])
            chart_labels = [h['run_date'][:10] for h in reversed(history)]  # Just date part, oldest to newest
            chart_scores = [h['cvss_score'] for h in reversed(history)]
            
            chart_id = f"chart-{test_name.replace('_', '-')}"
            
            html_content += f"""
                    <tr>
                        <td><code>{test_name}</code></td>
                        <td>{description}</td>
                        <td><span class="{status_class}">{status_icon} {status}</span></td>
                        <td>
                            <div class="cvss-score" style="font-size: 1.2rem;">{baseline_score:.1f}</div>
                            <span class="severity-badge" style="background-color: {baseline_color};">{baseline_severity}</span>
                        </td>
                        <td>
                            <div class="cvss-score" style="font-size: 1.2rem;">{current_score:.1f}</div>
                            <span class="severity-badge" style="background-color: {current_color};">{current_severity}</span>
                        </td>
                        <td>{improvement_html}</td>
                        <td>
                            <canvas id="{chart_id}" class="trend-chart"></canvas>
                        </td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
"""
    
    # Footer
    html_content += f"""
    </div>
    
    <div class="footer">
        <div class="container">
            <p><strong>OpenMRS O3 Continuous Security Testing Framework</strong></p>
            <p>CVSS 4.0 | Automated Vulnerability Assessment | NSF Research Project</p>
            <p><small>Methodology: Purkayastha BDD Approach | Dashboard Generated: {timestamp_est}</small></p>
        </div>
    </div>
    
    <script>
        // Chart.js configuration for trend visualization
        const chartConfig = {{
            type: 'line',
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return 'CVSS: ' + context.parsed.y.toFixed(1);
                            }}
                        }}
                    }}
                }},
                scales: {{
                    x: {{ display: false }},
                    y: {{
                        min: 0,
                        max: 10,
                        ticks: {{
                            stepSize: 2
                        }}
                    }}
                }}
            }}
        }};
"""
    
    # Generate Chart.js initialization for each test
    for score_data in all_scores:
        test_name = score_data['test_name']
        history = test_histories.get(test_name, [])
        
        chart_labels = [h['run_date'][:10] for h in reversed(history)]
        chart_scores = [h['cvss_score'] for h in reversed(history)]
        
        chart_id = f"chart-{test_name.replace('_', '-')}"
        
        html_content += f"""
        // Chart for {test_name}
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
                    pointRadius: 3,
                    pointHoverRadius: 5
                }}]
            }}
        }});
"""
    
    html_content += """
    </script>
</body>
</html>
"""
    
    # Write to file
    output_path = os.path.join(os.path.dirname(__file__), 'index.html')
    with open(output_path, 'w') as f:
        f.write(html_content)
    
    print(f"✅ Dashboard generated: {output_path}")
    print(f"   Tests displayed: {len(all_scores)}")
    print(f"   Timestamp: {timestamp_est}")


if __name__ == '__main__':
    generate_dashboard()