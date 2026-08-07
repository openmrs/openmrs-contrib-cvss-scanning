# Generate a comment displaying the differences between two reports

import sys
import json

def get_all_test_data(reportDict):
    
    # collect data for easy checking
    new_dict = {}
    
    json_tests = reportDict["tests"]
    for test in json_tests:
        new_dict[test["nodeid"]] = test["outcome"]
    
    return new_dict
        

def compare_test_data(new_tests:dict, prev_tests:dict):
    
    output = {
        "add": [],
        "sub": [],
        "pass_to_fail": [],
        "fail_to_pass": []
    }
    
    # get all test names
    all_test_names = []
    
    for key in new_tests.keys():
        all_test_names.append(key)
    
    for key in prev_tests.keys():
        if key not in all_test_names:
            all_test_names.append(key)
        
    for test_name in all_test_names:
        is_in_new = test_name in new_tests.keys()
        is_in_prev = test_name in prev_tests.keys()
        
        if is_in_new:
            pass_icon = "✅" if new_tests[test_name] == "passed" else "❌"
        
        # if in new & not prev
        if is_in_new and not is_in_prev:
            output["add"].append(f"➕ | {test_name} | {pass_icon}")
        
        # if in prev & not new
        elif is_in_prev and not is_in_new:
            output["sub"].append(f"➖ | {test_name} | N/A")
        
        # if in both
        elif is_in_new and is_in_prev:
            # if pass -> fail
            if prev_tests[test_name] == "passed" and new_tests[test_name] == "failed":
                output["pass_to_fail"].append(f"⚠️ | {test_name} | {pass_icon}")
            
            # if fail -> pass
            if prev_tests[test_name] == "failed" and new_tests[test_name] == "passed":
                output["fail_to_pass"].append(f"🎉 | {test_name} | {pass_icon}")
            
        else:
            print("Missing test name")
    
    return output

def create_comment(output:dict):
    
    # table header
    comment = "| Change | Test name | Status |\n|--------|-----------|--------|\n"
    
    # additions
    for key in output.keys():
        for test in output[key]:
            comment += f"{test}\n"
    
    return comment
        

def main():
    if len(sys.argv) != 3:
        print("Usage: python compare_reports.py <file1> <file2>")
        sys.exit(1)

    newReport, prevReport = sys.argv[1], sys.argv[2]
    newReportDict : dict = {}
    prevReportDict : dict = {}
    
    with open(newReport, "r") as file:
        newReportDict = json.load(file)
    
    with open(prevReport, "r") as file:
        prevReportDict = json.load(file)

    formatted_new_report = get_all_test_data(newReportDict)
    formatted_prev_report = get_all_test_data(prevReportDict)
    
    output = compare_test_data(formatted_new_report, formatted_prev_report)
    commentText = create_comment(output)
    
    with open('pr-comment.txt', 'w', encoding='utf-8') as f:
        f.write(commentText)

if __name__ == "__main__":
    main()