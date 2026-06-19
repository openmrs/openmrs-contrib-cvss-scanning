# Dashboard Generator
# Goal:
# 1. Extract relevant test data from JSON
# 2. Save relevant test data to DB
# 3. Filter test data
# 4. Display test data

import json
import html
import re

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
pie_chart_data = {
    "failed": {},
    "coverage": {},
    "category_colors": {},
}

def get_severity_class(severity, status="failed"):
    colors = {
        'CRITICAL': 'severity-critical',
        'HIGH': 'severity-high',
        'MEDIUM': 'severity-medium',
        'LOW': 'severity-low',
        'NONE': 'severity-none',
        'UNKNOWN': 'severity-unknown',
    }
    
    color = colors.get('NONE')
    
    if status != "passed":
        color = colors.get(severity, '.severity-unknown')
    
    return color

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
            'full_name':        "",
            'name':             "",
            'category':         "",
            'description':      "",
            'status':           "",
            'status_class':     "",
            'cvss_score':       "",
            'severity':         "",
            'severity_class':   "",
            'duration':         "",
            'params':           {},
            'errors':           "",
        }
        
        new_test["full_name"] = test.get("nodeid", "Could not find in report.")
        new_test["name"] = test.get("scenario", "Could not find in report.")
        new_test["category"] = test.get("feature", "Could not find in report.")
        new_test['description'] = test.get("scenario_description", "Could not find in report.")
        new_test['status'] = test.get("outcome", "Could not find in report.")
        new_test['status_class'] = "status-pass" if new_test['status'] == "passed" else "status-fail"
        
        new_test['cvss_score'] = test.get("cvss_score", "Could not find in report.")
        new_test['severity'] = test.get("severity", "Could not find in report.")
        new_test['severity_class'] = get_severity_class(new_test['severity'], new_test['status'])
        
        # parameter list
        params_dict : dict = test.get("params", {})
        new_test['params'] = []
        
        # if empty, add N/A
        if bool(params_dict) == False:
            new_test['params'].append("N/A")
        
        else:
            # add parameters as lines
            for key in params_dict.keys():
                param_str = f"{key}: {str(params_dict[key])}"
                param = html.escape(param_str, quote=True)
                new_test['params'].append(param)
            
        # duration
        setup_duration = test.get("setup", {}).get("duration", 0)
        call_duration = test.get("call", {}).get("duration", 0)
        teardown_duration = test.get("teardown", {}).get("duration", 0)
        
        new_test['duration'] = setup_duration + call_duration + teardown_duration
        
        # round
        if new_test['duration'] > 60:
            new_test['duration'] = new_test['duration'] / 60
            new_test['duration'] = round(new_test['duration'], 2)
            new_test['duration'] = f"{new_test['duration']}m"
        else:
            new_test['duration'] = round(new_test['duration'], 2)
            new_test['duration'] = f"{new_test['duration']}s"
        
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

def prepare_data():
    
    # get current time
    global current_time
    current_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # convert and round duration
    summary_data["duration"] = summary_data["duration"] / 60
    summary_data["duration"] = round(summary_data["duration"], 1)
    
    # get categories
    for test in tests:
        category:str = test["category"]
        if category not in (c["name"] for c in categories):
            
            new_category = {
                "name" : category,
                "total" : 0,
                "passed" : 0,
                "failed" : 0,
                "label" : "",
                "icon" : "",
                "id" : "",
                "max_cvss" : 0,
                "max_cvss_class" : "",
                "max_severity" : "UNKNOWN",
            }
            
            new_category["id"] = "cat_" + re.sub(r'[^a-zA-Z_]', '_', category)
            
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
                    if test["status"] == "failed":
                        category["max_cvss"] = test["cvss_score"]
        
        category["max_severity"] = get_cvss_severity(category["max_cvss"])
        
        category["max_severity_class"] = get_severity_class(category["max_severity"])
        
        category["icon"] = '✅' if category["failed"] == 0 else ('❌' if category["passed"] == 0 else '⚠️')
    
    # prepare pie charts
    prepare_pie_charts()

def prepare_pie_charts():
    # collect all failing categories
    # collect percent failing from total    
    pie_chart_data["failed"]["percents"] = []
    for i in range(0, len(categories)):
        if categories[i]["failed"] > 0:
            
            # calculate total failed out of all failed
            percent_failed = 100 * categories[i]["failed"] / summary_data["failed"]
            percent_failed = round(percent_failed, 2)
            
            pie_chart_data["failed"]["percents"].append([categories[i]["name"], percent_failed, categories[i]["id"]])
    
    # sort data
    pie_chart_data["failed"]["percents"].sort(key=lambda x: x[1])
    
    # collect total test coverage
    pie_chart_data["coverage"]["percents"] = []
    for i in range(0, len(categories)):
        if categories[i]["total"] > 0:
            
            # calculate total covered out of all tests
            percent_covered = 100 * categories[i]["total"] / summary_data["total"]
            percent_covered = round(percent_covered, 2)
            
            pie_chart_data["coverage"]["percents"].append([categories[i]["name"], percent_covered, categories[i]["id"]])
    
    # combine lower percent tests
    keepGoing = True
    current_index = 0
    current_sum = 0
    while keepGoing:
        category_percent = pie_chart_data["coverage"]["percents"][current_index][1]
        if category_percent < 5.0:
            current_sum += category_percent
            
            # remove from list
            pie_chart_data["coverage"]["percents"].pop(current_index)
        else:
            current_index += 1
        
        if current_index >= len(pie_chart_data["coverage"]["percents"]):
            keepGoing = False
    
    # sort data
    pie_chart_data["coverage"]["percents"].sort(key=lambda x: x[1])
    pie_chart_data["coverage"]["percents"].insert(0, ["Other", current_sum, "other"])

def display_pie_chart_css():
    # write custom css for pie chart
    
    html_colors = [
        "crimson", "teal", "gold", "coral",
        "darkorchid", "yellowgreen", "hotpink", "steelblue", "orange",
        "seagreen", "mediumpurple", "tomato", "cornflowerblue", "peru",
        "limegreen", "deeppink", "dodgerblue", "sienna", "darkturquoise",
        "indigo", "darkorange", "cadetblue", "firebrick", "mediumseagreen",
        "slateblue", "salmon", "olivedrab", "mediumvioletred", "yellow",
    ]
    
    pie_chart_css = ":root {\n"
    
    # failed tests
    current_percent = 0
    for category in pie_chart_data["failed"]["percents"]:
        category_id = category[2]
        current_percent += category[1]
        current_percent = round(current_percent)
        current_percent = min(100.0, current_percent)
        pie_chart_css += f"  --fail_{category_id}: {current_percent}%;\n"
    
    # test coverage
    # failed tests
    current_percent = 0
    for category in pie_chart_data["coverage"]["percents"]:
        category_id = category[2]
        current_percent += category[1]
        current_percent = round(current_percent)
        current_percent = min(100.0, current_percent)
        pie_chart_css += f"  --coverage_{category_id}: {current_percent}%;\n"
    
    pie_chart_css += """}
.chart-container-failed-tests {
    background: conic-gradient("""
    
    for i in range(0, len(pie_chart_data["failed"]["percents"])):
        
        category = pie_chart_data["failed"]["percents"][i]
        
        # set HTML color
        category_id = category[2]
        
        if category_id not in pie_chart_data["category_colors"]:
            pie_chart_data["category_colors"][category_id] = html_colors.pop()
        
        color = pie_chart_data["category_colors"][category_id]
        
        if i == 0:
            pie_chart_css += f"{color} 0% var(--fail_{category_id})"
        else:
            prev_category = pie_chart_data["failed"]["percents"][i-1]
            prev_category_id = prev_category[2]
            
            pie_chart_css += f"{color} var(--fail_{prev_category_id}) var(--fail_{category_id})"
        
        if i != len(pie_chart_data["failed"]["percents"]) - 1:
            pie_chart_css += ","
        
        pie_chart_css += "\n"
    
    pie_chart_css += """
    );
}"""
    
    pie_chart_css += """
.chart-container-total-tests {
    background: conic-gradient("""
    
    for i in range(0, len(pie_chart_data["coverage"]["percents"])):
        
        category = pie_chart_data["coverage"]["percents"][i]
        
        # set HTML color
        category_id = category[2]
        if category_id not in pie_chart_data["category_colors"]:
            pie_chart_data["category_colors"][category_id] = html_colors.pop()
        color = pie_chart_data["category_colors"][category_id]
        
        if i == 0:
            pie_chart_css += f"{color} 0% var(--coverage_{category_id})"
        else:
            prev_category = pie_chart_data["coverage"]["percents"][i-1]
            prev_category_id = prev_category[2]
            
            pie_chart_css += f"{color} var(--coverage_{prev_category_id}) var(--coverage_{category_id})"
        
        if i != len(pie_chart_data["coverage"]["percents"]) - 1:
            pie_chart_css += ","
        
        pie_chart_css += "\n"
    
    pie_chart_css += """
    );
}"""

    for key in pie_chart_data["category_colors"].keys():
        category_id = key
        color = pie_chart_data["category_colors"][category_id]
        
        pie_chart_css += f"\n.category_color_{category_id} {{ background: {color}; }}"
    
    with open("assets/pie_chart.css", "w") as f:
        f.write(pie_chart_css)

def display_test_data():

    display_pie_chart_css()

    # load template
    env = Environment(loader = FileSystemLoader('assets/templates'))
    template = env.get_template('security_dashboard_template.html')
    
    output = template.render(
        summary_data = summary_data,
        tests = tests,
        current_time = current_time,
        categories = categories,
        pie_chart_data = pie_chart_data,
    )
        
    # save to file
    with open("assets/renders/security_dashboard.html", 'w', encoding="utf-8") as f:
        f.write(output)


if __name__ == "__main__":
    extract_relevant_test_data()
    prepare_data()
    display_test_data()