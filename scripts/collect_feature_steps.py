# Go through the tests/ directory and pull out all steps

from pathlib import Path
from gherkin.parser import Parser
from gherkin.token_scanner import TokenScanner

feature_file_paths = []
saved_steps = []

# for all files in tests/
def find_files_in_path(path):
    for path in path.iterdir():
        
        if path.is_file():
            if is_feature_file(path):
                feature_file_paths.append(path)
        
        elif path.is_dir():
            find_files_in_path(path)

def is_feature_file(path):
    
    is_feature = False
    
    if path.suffix == ".feature":
        is_feature = True
    
    return is_feature

def find_steps(path):
    
    parser = Parser()
    with open(path, encoding='utf-8') as f:
        text = f.read()
    
    gherkin_doc = parser.parse(TokenScanner(text))
    feature = gherkin_doc["feature"]
    children = feature["children"]
    
    for child in children:
        
        child_key = ""
        
        if "scenario" in child:
            child_key = "scenario"
        elif "background" in child:
            child_key = "background"
            
        child_dict = child[child_key]
        steps = child_dict["steps"]
        
        for step in steps:
            if step["text"] not in saved_steps:
                saved_steps.append(step["text"])

# find feature files
find_files_in_path(Path('tests'))

# find steps
for feature_path in feature_file_paths:
        find_steps(feature_path)
# Write to files
with open('feature_steps.txt', 'w', encoding='utf-8') as f:    
    for step in saved_steps:
        f.write(step + "\n")