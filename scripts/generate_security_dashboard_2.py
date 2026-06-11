# Dashboard Generator
# Goal:
# 1. Extract relevant test data from JSON
# 2. Save relevant test data to DB
# 3. Filter test data
# 4. Display test data

import json
import html

JSON_REPORT_PATH = 'report.json'

summary_data : dict = {
    "failed" : 0,
    "passed" : 0,
    "total" : 0,
    "duration" : 0,
}

tests = []

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

def display_test_data():
    for test in tests:
        print(test)
        print()

if __name__ == "__main__":
    extract_relevant_test_data()
    display_test_data()