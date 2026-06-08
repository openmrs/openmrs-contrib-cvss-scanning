#!/usr/bin/env python3
"""
OpenMRS O3 Security Dashboard Generator
Parses test results and generates HTML dashboard with CVSS scores

CVSS 4.0 Migration: Automatically extracts test descriptions from docstrings
"""

import json
import html
import re
import sys
import sqlite3
import os
import html as html_lib
from datetime import datetime
from datetime import timezone
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'test_results.db')

def init_db():
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
    c.execute('''
        CREATE TABLE IF NOT EXISTS category_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            max_cvss REAL NOT NULL,
            run_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_test_result(test_name, cvss_score, status):
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


def save_category_max_cvss(category, max_cvss):
    if max_cvss is None:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute(
        'INSERT INTO category_history (category, max_cvss, run_at) VALUES (?, ?, ?)',
        (category, max_cvss, now)
    )
    conn.commit()
    conn.close()


def get_baseline(test_name):
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


def get_category_history(category, limit=20):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            'SELECT max_cvss FROM category_history WHERE category = ? ORDER BY run_at DESC LIMIT ?',
            (category, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in reversed(rows)]
    except Exception as e:
        print(f'Warning: Could not get category history for {category}: {e}')
        return []


def generate_category_trend_html(category, history, max_cvss):
    safe_id = ''.join(c if c.isalnum() else '_' for c in category)
    chart_id = f"cat_trend_{safe_id}"

    # Improvement badge vs category baseline (first recorded max_cvss)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT max_cvss FROM category_history WHERE category = ? ORDER BY run_at ASC LIMIT 1', (category,))
        row = c.fetchone()
        conn.close()
        cat_baseline = row[0] if row else None
    except Exception as e:
        print(f'Warning: Could not get category baseline for {category}: {e}')
        cat_baseline = None

    if cat_baseline is not None and max_cvss is not None:
        improvement = round(cat_baseline - max_cvss, 1)
        if improvement > 0:
            improvement_badge = f'<span style="color:#28a745; font-weight:bold; font-size:11px;">+{improvement:.1f} ↑</span>'
        elif improvement < 0:
            improvement_badge = f'<span style="color:#dc3545; font-weight:bold; font-size:11px;">{improvement:.1f} ↓</span>'
        else:
            improvement_badge = '<span style="color:#718096; font-size:11px;">0.0 —</span>'
    else:
        improvement_badge = ''

    if len(history) < 2:
        return f'{improvement_badge} <span style="color:#a0aec0; font-size:11px;">Not enough data</span>'

    history_json = json.dumps(history)
    labels_json = json.dumps([f"Run {i+1}" for i in range(len(history))])

    return f'''{improvement_badge}<canvas id="{chart_id}" width="100" height="28" style="vertical-align:middle; display:block;"></canvas>
    <script>
    new Chart(document.getElementById("{chart_id}"), {{
        type: "line",
        data: {{
            labels: {labels_json},
            datasets: [{{
                data: {history_json},
                borderColor: "#e53e3e",
                borderWidth: 1.5,
                pointRadius: 1.5,
                fill: false,
                tension: 0.3
            }}]
        }},
        options: {{
            plugins: {{ legend: {{ display: false }}, tooltip: {{
                callbacks: {{
                    title: function(items) {{ return items[0].label; }},
                    label: function(item) {{ return "Max CVSS: " + item.parsed.y.toFixed(1); }}
                }}
            }} }},
            scales: {{
                x: {{ display: false }},
                y: {{ display: false, min: 0, max: 10 }}
            }},
            animation: false
        }}
    }});
    </script>'''


def get_test_description_from_docstring(test_nodeid):
    try:
        if '::' not in test_nodeid:
            return get_test_description_fallback(test_nodeid)
        
        file_path, test_name = test_nodeid.split('::')
        
        abs_path = Path("tests/" + file_path).resolve()
                
        if not abs_path.exists():
            print(f"Warning: Test file not found: {abs_path}")
            return get_test_description_fallback(test_name)
        
        with open(abs_path, 'r', encoding="utf-8") as f:
            content = f.read()
        
        pattern = rf'def {re.escape(test_name)}\([^)]*\):\s*"""(.*?)"""'
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            docstring = match.group(1).strip()
            lines = [line.strip() for line in docstring.split('\n') if line.strip()]
            description = ' '.join(lines)
            
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
    
    for key, desc in descriptions.items():
        if key in test_name:
            return desc
    
    readable_name = test_name.replace('test_', '').replace('_', ' ').title()
    return f'{readable_name} security test'

def get_severity_color(severity):
    colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
        'NONE': '#6c757d',
        'UNKNOWN': '#6c757d',
    }
    return colors.get(severity, '#6c757d')

def get_cvss_severity(cvss_score):
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return severity

def parse_test_results():
    try:
        with open('report.json', 'r') as f:
            json_report = json.load(f)
    except FileNotFoundError:
        print("Error: report.json not found")
        sys.exit(1)
    
    try:
        with open('test_output.log', 'r') as f:
            log_content = f.read()
    except FileNotFoundError:
        print("Warning: test_output.log not found")
        log_content = ""
    
    results = []
    
    for test in json_report.get('tests', []):
        test_name = test.get('nodeid', 'Unknown Test')
        
        status = 'PASS' if test.get('outcome') == 'passed' else 'FAIL'
        
        file_path = test_name.split('::')[0]
        path_parts = file_path.split('/')
        if len(path_parts) >= 2:
            category = path_parts[-2]
        else:
            category = 'uncategorized'

        duration = test.get('call', {}).get('duration', 0)
        
        if duration == 0 or duration is None:
            setup_duration = test.get('setup', {}).get('duration', 0) or 0
            call_duration = test.get('call', {}).get('duration', 0) or 0
            teardown_duration = test.get('teardown', {}).get('duration', 0) or 0
            duration = setup_duration + call_duration + teardown_duration
        
        cvss_score = test.get('cvss_score')
        severity = test.get('severity')
        
        description = test.get("scenario_description", "No description available")
        
        category = test.get("feature", "No feature found")
        scenario = test.get("scenario", "No scenario found")
        
        params_match = re.search(re.compile(r"\[.+\]"), test_name)
        params = "N/A"
        if params_match:
            params = params_match.group(0)[1:-1]
            params = html.escape(params, quote=True)
        
        error_text = test.get('call', {}).get('longrepr', None)
        arrow_line = ""
        error_lines = []
        
        if error_text:
            error_text = error_text.split('\n')
            
            for i in range(0, len(error_text)):
                if len(error_text[i]) >= 2:
                    
                    if error_text[i][:2] == "> ":
                        line:str = error_text[i][1:]
                        line = line.strip()
                        line = html.escape(line, quote=True)
                        arrow_line = line
                    
                    if error_text[i][:2] == "E ":
                        line:str = error_text[i][1:]
                        line = line.strip()
                        line = html.escape(line, quote=True)
                        error_lines.append(line)
                        
        error_lines.insert(0, arrow_line)
        
        results.append({
            'full_name': test_name,
            'name': test_name,
            'category': category,
            'scenario': scenario,
            'description': description,
            'status': status,
            'cvss_score': cvss_score,
            'severity': severity,
            'duration': duration,
            'params': params,
            'errors':error_lines,
        })
    grouped = {}
    for r in results:
        grouped.setdefault(r['category'], []).append(r)

    return grouped, json_report.get('summary', {})


def generate_dashboard_html_header():
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenMRS O3 Security Dashboard - CVSS 4.0 Migration</title>
    <link rel="stylesheet" href="assets/security_dashboard.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <script>
        function toggleCategory(id) {{
            const body    = document.getElementById(id);
            const chevron = document.getElementById('chevron_' + id);
            const isOpen  = body.classList.toggle('open');
            chevron.classList.toggle('open', isOpen);
        }}
    </script>
    <script>
        function showDiv(id){{
            const divs = document.querySelectorAll("#tabs_div>div");
            divs.forEach(d=>{{d.classList.remove("visible")}});
            document.getElementById(id).classList.add("visible");
        }}
    </script>
</head>"""

def generate_dashboard_page_header():
    utc = timezone.utc
    now = datetime.now(utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    return f"""      <div class="header">
            <h1>🔒 OpenMRS O3 Security Dashboard</h1>
            <p>Continuous Security Testing with CVSS Vulnerability Scoring</p>
            <p class="timestamp-line">Last Updated: 
            <span class="timestamp">
                {now}
            </span>
            </p>
        </div>\n"""

def generate_dashboard_vulnerability_testing(grouped_results, summary):
    all_results = [r for group in grouped_results.values() for r in group]
    total_duration_sec = sum(r['duration'] for r in all_results)
    total_duration_min = total_duration_sec / 60
    html = f"""     
    <div id ="vulnerability_testing">
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
        </div>"""

    for category, results in grouped_results.items():
        cat_total  = len(results)
        cat_passed = sum(1 for r in results if r['status'] == 'PASS')
        cat_failed = cat_total - cat_passed
        cat_label  = category.replace('_', ' ').title()

        cat_icon = '✅' if cat_failed == 0 else ('❌' if cat_passed == 0 else '⚠️')

        cat_id = f"cat_{category}"

        failed_cvss_scores = [
            r['cvss_score'] for r in results
            if r['status'] == 'FAIL' and r['cvss_score'] is not None
        ]
        max_cvss = max(failed_cvss_scores) if failed_cvss_scores else 0.0

        save_category_max_cvss(category, max_cvss)
        cat_history = get_category_history(category)

        if max_cvss is not None:
            max_severity = max_cvss
            max_severity_color = get_severity_color(get_cvss_severity(max_severity))
            cvss_badge_html = (
                f'<span style="background-color:{max_severity_color}; color:white; '
                f'font-weight:600; font-size:12px; padding:3px 10px; '
                f'border-radius:10px; margin-right:8px;">'
                f'Highest CVSS: {max_cvss:.1f} — {get_cvss_severity(max_severity)}</span>'
            )
        else:
            cvss_badge_html = ''

        cat_trend_html = generate_category_trend_html(category, cat_history, max_cvss)
        cat_trend_block = f'''<span class="cat-trend-wrapper">
                    <span class="cat-trend-label">Max CVSS trend:</span>
                    {cat_trend_html}
                </span>'''

        html += f"""
        <div class="test-results">
            <div class="category-header" onclick="toggleCategory('{cat_id}')">
                <span class="category-title">
                    {cat_icon}&nbsp;{cat_label}
                </span>
                <span class="category-meta">
                    {cvss_badge_html}
                    {cat_trend_block}
                    <span class="category-header passed">{cat_passed} passed</span>
                    &nbsp;/&nbsp;
                    <span class="category-header failed">{cat_failed} failed</span>
                    &nbsp;·&nbsp;{cat_total} test{'s' if cat_total != 1 else ''}
                    <span class="chevron" id="chevron_{cat_id}">▼</span>
                </span>
            </div>
            <div class="category-body" id="{cat_id}">\n"""

        failed_results = [r for r in results if r['status'] == 'FAIL']
        passed_results = [r for r in results if r['status'] == 'PASS']

        TABLE_HEADER = """
                <table>
                    <thead>
                        <tr>
                            <th>Test Name</th>
                            <th>Parameters</th>
                            <th>Description</th>
                            <th>Status</th>
                            <th>CVSS Score (Baseline)</th>
                            <th>Severity</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>\n"""

        def render_rows(rows, category):
            out = ""
            for r in rows:
                status_class   = 'status-pass' if r['status'] == 'PASS' else 'status-fail'
                severity_color = get_severity_color(r['severity'])
                cvss_display   = f"{r['cvss_score']:.1f}" if r['cvss_score'] is not None else 'N/A'

                duration = r['duration']
                duration_display = f"{duration/60:.1f}m" if duration >= 60 else f"{duration:.2f}s"


                safe_id_name = ''.join(c if c.isalnum() else '_' for c in r['name'])
                chart_id     = f"chart_{category}_{safe_id_name}"

                param_display = (
                    f' <span style="font-size:11px; color:#718096; font-weight:400;">'
                    f'[{html_lib.escape(r["param"])}]</span>'
                    if r.get('param') else ''
                )

                if r['name'].find("/") !=-1:
                    r['name']=r['name'].split("/")[1]
                if r['name'].find("::") !=-1:
                    r['name']=r['name'].split("::")[0]

                if r['status'] == 'PASS':
                    out += f"""
                        <tr>
                            <td><strong>{r['scenario'].title()}</strong>{param_display}</td>
                            <td>{r['params']}</td>
                            <td>{r['description']}</td>
                            <td><span class="status-badge {status_class}">{r['status']}</span></td>
                            <td><span class="cvss-score-pass">{cvss_display}</span></td>
                            <td><span class="severity-badge" style="background-color: {get_severity_color("NONE")};">{r['severity']}</span></td>
                            <td>{duration_display}</td>
                        </tr>\n"""
                else:
                    error_text = ""
                    for i in range(0, len(r["errors"])):
                        error_text += "<p>" + r["errors"][i] + "</p>"
                    
                    out += f"""
                        <tr>
                            <td>
                            <strong>{r['scenario'].title()}</strong>{param_display}
                            </td>
                            <td><span class="parameters">{r['params']}</span></td>
                            <td>{r['description']}</td>
                            <td><span class="status-badge {status_class}">{r['status']}</span></td>
                            <td>
                            <div class="tooltip">
                                    <span class="cvss-score-fail">{cvss_display}</span>
                                    <span class="tooltiptext">
                                        <p><u>Recorded Errors</u></p>
                                        {error_text}
                                    </span>
                                </div>
                            </td>
                            <td><span class="severity-badge" style="background-color: {severity_color};">{r['severity']}</span></td>
                            <td>{duration_display}</td>
                        </tr>\n"""
            return out

        if failed_results:
            html += f"""
                <details open>
                    <summary class="subcategory-summary subcategory-fail">
                        <span>Failed Tests</span>
                        <span class="subcategory-count">{len(failed_results)} test{'s' if len(failed_results) != 1 else ''}</span>
                    </summary>
                    {TABLE_HEADER}
                    {render_rows(failed_results, category)}
                    </tbody>
                </table>
                </details>\n"""

        if passed_results:
            html += f"""
                <details open>
                    <summary class="subcategory-summary subcategory-pass">
                        <span>Passed Tests</span>
                        <span class="subcategory-count">{len(passed_results)} test{'s' if len(passed_results) != 1 else ''}</span>
                    </summary>
                    {TABLE_HEADER}
                    {render_rows(passed_results, category)}
                    </tbody>
                </table>
                </details>\n"""

        html += """
            </div>
        </div>\n"""

    html += """
    </div>\n""" 

    return html

#Buttons to select tabs
def generate_dashboard_tabs_buttons():
    html = """  <div class = "tabs_buttons">
        <button style="margin-right:5px;" onclick='showDiv("vulnerability_testing")'><b>Vulnerability Tests</b></button>
        <button style="margin-left:5px;" onclick='showDiv("dependency_scanning")'><b>Dependency Scanning</b></button>
    </div>\n"""
    return html

def generate_dependency_scanning_tab():
    html = f""" <div id="dependency_scanning">
        <iframe src="https://openmrs.github.io/openmrs-contrib-dependency-vulnerability-dashboard/"></iframe>
    </div>"""
    return html

def generate_html_dashboard(grouped_results, summary):
    html = generate_dashboard_html_header()
    html += f"""
<body  onload='showDiv("vulnerability_testing")'>
    {generate_dashboard_page_header()}
    {generate_dashboard_tabs_buttons()}
    <div id="tabs_div">
        {generate_dashboard_vulnerability_testing(grouped_results, summary)}
        {generate_dependency_scanning_tab()}
    </div>\n"""
    html += """
        <div class="footer">
            <p>OpenMRS O3 Continuous Security Testing</p>
            <p>Powered by <a href="https://www.first.org/cvss/v4.0/" target="_blank">CVSS 4.0</a> | 
            <a href="https://github.com/openmrs/openmrs-contrib-cvss-scanning" target="_blank">GitHub Repository</a> | <a href='/detailed-report.html'>PyTest Report</a></p>
        </div>
    </div>
</body>
</html>\n"""

    return html


def main():
    print("="*70)
    print("OpenMRS O3 Security Dashboard Generator")
    print("="*70)
    print("")
    
    print("Initializing database...")
    init_db()

    print("Parsing test results...")
    results, summary = parse_test_results()
    total = sum(len(v) for v in results.values())
    print(f"Found {total} test(s)")

    print("")
    print("Saving test results to database...")
    for category_results in results.values():
        for r in category_results:
            save_test_result(r['name'], r['cvss_score'], r['status'])
    print("✓ Test results saved")

    print("")
    print("Generating HTML dashboard...")
    html_content = generate_html_dashboard(results, summary)
    
    with open('security_dashboard.html', 'w', encoding="utf-8") as f:
        f.write(html_content)
    
    print("✓ Dashboard saved to security_dashboard.html")
    print("")
    print("="*70)


if __name__ == '__main__':
    main()