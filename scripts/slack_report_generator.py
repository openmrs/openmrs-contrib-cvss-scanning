import json
import sys
import sqlite3
from datetime import datetime

def get_category_history(category,db_path, limit=20 ):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute(
            'SELECT run_at FROM category_history WHERE category = ? ORDER BY run_at ASC LIMIT ?',
            (category, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in rows]
    except Exception as e:
        print(f'Warning: Could not get category history for {category}: {e}')
        #return a greater cvss score than is possible so the email doesn't print the category as failing - we can't necessicarily know
        return [11]

def parse_test_results(file_name):
    try:
        with open(file_name, 'r') as f:
            json_report = json.load(f)
    except FileNotFoundError:
        print("Error: report.json not found")
        sys.exit(1)
    
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
        })
    grouped = {}
    for r in results:
        grouped.setdefault(r['category'], []).append(r)

    return grouped, json_report.get('summary', {})

def main():

    data = parse_test_results(sys.argv[1])
    resultString = ""

    new_categories=[]
    for category in data[0]:
        category_history = get_category_history(category,sys.argv[2],2)
        #since we are ordering by ascending, the oldest run_at is selected, and we can compare that to today's date to see if the tests are first ran within a day
        time = datetime.fromisoformat(category_history[0])
        today = datetime.today()
        difference = today-time
        duration_seconds = difference.total_seconds()
        #86400 is seconds in a day
        if(duration_seconds < 86400):
            new_categories.append(category)

    if(len(new_categories)>0):
        resultString= f"Additionally, there are {len(new_categories)} new test categories, which will need new tests written for them:\n"
        for category in new_categories:
            resultString+=f"{category}, "

    print(resultString)
main()