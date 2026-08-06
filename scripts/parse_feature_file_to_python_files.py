# The goal of this file is to read in a feature file and create corresponing python files
# that are filled in with the correct data

import os
import re
import json
from gherkin.parser import Parser

def select_category() -> str:
    """Asks for a test category and returns the path to the category directory"""
    
    # ask user for directory of feature
    user = input("Which category directory would you like to generate?")
    
    # get all files in corresponding directory
    path = os.path.join(os.getcwd(), "tests", user)
    
    return path

def get_feature_file(path:str) -> str:
    """Returns path to feature file of a given category"""
    
    allFiles = os.listdir(path=path)
    
    feature = ""
    
    for file in allFiles:
        # find feature file
        if re.search("\.feature$", file):
            # found feature file
            feature = file
    
    if feature == "":
        exit()
    
    return feature

def read_feature_file_as_json(path:str) -> dict:
    """Given the path to a category dir, this returns the JSON dictionary represnting the feature file inside"""
    
    feature = get_feature_file(path)
    
    feature_path = os.path.join(path, feature)
    
    # read this feature file in to a dictionary
    with open(feature_path, 'r') as f:
        feature_content = f.read()
    
    parser = Parser()
    gherkin_document = parser.parse(feature_content)
    
    return gherkin_document

def read_boilerplate() -> dict:
    """Returns the boilderplate code as JSON"""
    
    boilerplate_path = "./assets/boilerplate.json"
    
    with open(boilerplate_path) as json_file:
        data = json.load(json_file)
        
        return data

def generate_files(category_path:str, feature_dict:dict, boilerplate:dict):
    """Generates python files using the boilerplate and feature data"""
    
    # get a list of scenarios for the feature file
    
    scenarios = feature_dict['feature']['children'][1:]
    
    # assume the background is in the conftest
    
    # for each scenario
    for scen in scenarios:
        # create a file
        create_file(category_path, scen, boilerplate)

def format_name_as_variable(var:str):
    var = var.strip()
    var = var.lower()
    var = var.replace(" ", "_")
    
    return var

def create_file(category_path:str, scenario:dict, boilerplate:dict):
    """Creates a python file in the specified category"""
    
    feature_path = get_feature_file(category_dir)
    
    new_file_name : str = scenario['scenario']['name']
    new_file_name = format_name_as_variable(new_file_name)
    
    scenario_name : str = new_file_name
    new_file_name = "test_" + new_file_name + ".py"
        
    # DO NOT OVERWRITE EXISTING FILES
    if os.path.isfile(os.path.join(category_path, new_file_name)):
        # file exists
        return
    
    # create file
    file_contents : str = ""
    
    # add header info
    file_contents += boilerplate['header']
    
    # for steps in scenario
    steps : list = scenario['scenario']['steps']
    
    # write given CVSS
    file_contents += "\n" + boilerplate["given_cvss"] + "\n"
    
    # write scenario
    current_scenario_content : str = "\n" + boilerplate["scenario"]
    
    current_scenario_content = current_scenario_content.format(feature_path, scenario['scenario']['name'], scenario_name)
    file_contents += current_scenario_content
    
    current_step : str = ""
    
    for step in steps:
        index : str = step["keyword"]
        
        index = index.strip()
        index = index.lower()
        
        if index in ["given", "when", "then"]:
            current_step = index
        
        if index in ["and", "but"]:
            index = current_step
        
        current_content : str = boilerplate[index]
        current_content = current_content.format(step['text'], format_name_as_variable(step['text']))
        
        print(current_content)
        
        file_contents += "\n" + current_content + "\n"
    
    # add footer info
    file_contents += "\n" + boilerplate['footer']
    
    # write to file
    with open(os.path.join(category_path, new_file_name), 'w') as newfile:
        newfile.write(file_contents)

if __name__ == "__main__":
    category_dir : str = select_category()
    feature_dict : dict = read_feature_file_as_json(category_dir)
    boilerplate : dict = read_boilerplate()
    
    generate_files(category_dir, feature_dict, boilerplate)
    
    