# Dashboard Generator
# Goal:
# 1. Extract relevant test data from JSON
# 2. Save relevant test data to DB
# 3. Filter test data
# 4. Display test data

import json
import html

from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

JSON_REPORT_PATH = 'report.json'

summary_data : dict = {
    "failed" : 0,
    "passed" : 0,
    "total" : 0,
    "duration" : 0,
}
tests = []
current_time = None
categories = []

def extract_relevant_test_data():

    report = None

    # import JSON
    try:
        with open(JSON_REPORT_PATH, 'r') as report_file:
            report = json.load(report_file)

    except:
        print("Could not load JSON file")
    
    # get summary data
    report_summary = report['summary']
    
    summary_data["duration"] = report['duration']
    summary_data["failed"] = report_summary['failed']
    summary_data["passed"] = report_summary['passed']
    summary_data["total"] = report_summary['total']
    
    # extract relevant test data
    report_tests = report["tests"]
    
    for test in report_tests:
        new_test = {
            'full_name':    "",
            'name':         "",
            'category':     "",
            'scenario':     "",
            'description':  "",
            'status':       "",
            'cvss_score':   "",
            'severity':     "",
            'duration':     "",
            'params':       "",
            'errors':       "",
        }
        
        new_test["full_name"] = test.get("nodeid", "Could not find in report.")
        new_test["name"] = test.get("scenario", "Could not find in report.")
        new_test["category"] = test.get("feature", "Could not find in report.")
        new_test['scenario'] = test.get("scenario", "Could not find in report.")
        new_test['description'] = test.get("scenario_description", "Could not find in report.")
        new_test['status'] = test.get("outcome", "Could not find in report.")
        new_test['cvss_score'] = test.get("cvss_score", "Could not find in report.")
        new_test['severity'] = test.get("severity", "Could not find in report.")
        new_test['params'] = test.get("params", {})
    
        # duration
        setup_duration = test.get("setup", {}).get("duration", 0)
        call_duration = test.get("call", {}).get("duration", 0)
        teardown_duration = test.get("teardown", {}).get("duration", 0)
        
        new_test['duration'] = setup_duration + call_duration + teardown_duration
        
        # get minutes
        new_test['duration'] = new_test['duration'] / 60
        
        # errors
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
        
        new_test['errors'] = error_lines
    
        # append test
        tests.append(new_test)

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

def get_severity_class(severity):
    colors = {
        'CRITICAL': 'severity-critical',
        'HIGH': 'severity-high',
        'MEDIUM': 'severity-medium',
        'LOW': 'severity-low',
        'NONE': 'severity-none',
        'UNKNOWN': 'severity-unknown',
    }
    return colors.get(severity, '.severity-unknown')

def prepare_data():
    
    # get current time
    global current_time
    current_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # convert and round duration
    summary_data["duration"] = summary_data["duration"] / 60
    summary_data["duration"] = round(summary_data["duration"], 1)
    
    # get categories
    for test in tests:
        category = test["category"]
        if category not in (c["name"] for c in categories):
            
            new_category = {
                "name" : category,
                "total" : 0,
                "passed" : 0,
                "failed" : 0,
                "label" : "",
                "icon" : "",
                "id" : f"cat_{category}",
                "max_cvss" : 0,
                "max_cvss_class" : "",
                "max_severity" : "UNKNOWN",
            }
            
            categories.append(new_category)

    # get category stats
    for category in categories:
        for test in tests:
            if test["category"] == category["name"]:
                # collect stats
                category["total"] += 1
                
                if test["status"] == "passed":
                    category["passed"] += 1
                elif test["status"] == "failed":
                    category["failed"] += 1
                
                # cvss
                if test["cvss_score"] > category["max_cvss"]:
                    category["max_cvss"] = test["cvss_score"]
        
        category["max_severity"] = get_cvss_severity(category["max_cvss"])
        
        category["max_severity_class"] = get_severity_class(category["max_severity"])
        
        category["icon"] = '✅' if category["failed"] == 0 else ('❌' if category["passed"] == 0 else '⚠️')

def display_test_data():
    # load template
    env = Environment(loader = FileSystemLoader('assets/templates'))
    template = env.get_template('security_dashboard_template.html')
    
    output = template.render(
        summary_data = summary_data,
        tests = tests,
        current_time = current_time,
        categories = categories,
    )
        
    # save to file
    with open("assets/renders/security_dashboard.html", 'w', encoding="utf-8") as f:
        f.write(output)


if __name__ == "__main__":
    extract_relevant_test_data()
    prepare_data()
    display_test_data()