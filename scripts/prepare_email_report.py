import json
import sys
import sqlite3
from datetime import datetime

def get_category_history_score(category,db_path, limit=20 ):
    try:
        conn = sqlite3.connect(db_path)
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
        #return a greater cvss score than is possible so the email doesn't print the category as failing - we can't necessicarily know
        return [11]

def get_category_history_date(category,db_path, limit=20 ):
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
    #REQUIRED CLI ARGS: argv[1] is the test report json file name, argv[2] is the test results db file name.
    #read cli arg for report url
    file_name = sys.argv[1]
    #use function to extract json
    data = parse_test_results(file_name)

    #prepare email 
    email_text = """This is an automated email triggered by the automated security tests, viewed <a href = 'https://security-dashboard.openmrs.org/'>here</a>. <br> 
Testing indicates several failing tests of high or critical severity, as defined by CVSS 4.0. <br>
Please see the <a href = 'https://github.com/openmrs/openmrs-contrib-cvss-scanning'>GitHub repository's</a> tests directory for the tests themselves. <br>"""
    email_text += "\nThe failing tests and their CVSS scores follow:<br><br>\n"

    failing_categories =[]
    failing_categories_max_cvss={}
    add_br = False

    #scan failing tests for CVSS scores > 7 and the max failing test in each category
    for category in data[0]:
        if(add_br):
            email_text += "<br>"
            add_br=False
        for test in data[0][category]:
            if test['cvss_score']>=7 and test['status'] == "FAIL":
                if(category not in failing_categories):
                    failing_categories.insert(0,category)
                    email_text+=f"\n{category}:<br>\n"
                    add_br=True
                test_file = test["full_name"].split("::")[0].split("/")
                test_file = test_file[len(test_file)-1]
                email_text+= f"<b>{test_file}</b> : {test['cvss_score']} <br>\n"
            if test['status'] == "FAIL":
                if(category not in failing_categories_max_cvss):
                    failing_categories_max_cvss[category]= test['cvss_score']
                if failing_categories_max_cvss[category] < test['cvss_score']:
                    failing_categories_max_cvss[category] = test['cvss_score']

    #scan for failing tests with cvss 9.0 or greater, save test file, cvss score
    if(len(failing_categories)==0 and len(failing_categories_max_cvss)==0):
        email_text+="\nNO FAILING TESTS\n"
    elif (len(failing_categories)==0):
        email_text+= "No tests failed with a high or critical score.<br>"

    categories_with_score_increase = {}

    if(len(failing_categories_max_cvss)>=1):
        #only need to run this if there are failing tests, no failing tests is good and means there aren't 
        try:
            for category in failing_categories_max_cvss:
                #get cvss history for category
                category_history = get_category_history_score(category,sys.argv[2],1)
                #see if the test historic score is < than the max
                max_increase = 0
                for point in category_history:
                    if(failing_categories_max_cvss[category]>point):
                        increase = failing_categories_max_cvss[category]-category_history
                        if(increase>max_increase):
                            max_increase=increase
                if(max_increase!=0):
                    categories_with_score_increase[category] = failing_categories_max_cvss[category]-category_history
        except:
            "ignore category"

    if(len(categories_with_score_increase) >1):
        email_text += "\n<br>These testing categories saw their highest testing CVSS score increase: <br>\n"
        for category in categories_with_score_increase:
            email_text += f"<b>{category}</b>: +{categories_with_score_increase[category]}<br>\n"

    #new categories, 
    new_categories=[]
    for category in data[0]:
        print(category)
        category_history = get_category_history_date(category,sys.argv[2],1)
        #since we are ordering by ascending, the oldest run_at is selected, and we can compare that to today's date to see if the tests are first ran within a day
        time = datetime.fromisoformat(category_history[0])
        today = datetime.today()
        difference = today-time
        duration_seconds = difference.total_seconds()
        #86400 is seconds in a day
        if(duration_seconds < 86400):
            new_categories.append(category)
        
    if(len(new_categories)>0):
        email_text+=f"\nThere were {len(new_categories)} new testing categories created in the last week, that will need new tests written for them. The new categories are:<br>\n"
        email_text+="<b>"
        for category in new_categories:
            email_text+=f"{category}, "
        email_text+="</b><br>"
        

    #save email to file
    file = open("email_body.html","w+")
    file.write(email_text)
    file.close()
main()