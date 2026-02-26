/*


*/
featureFileString="";
testScaffoldStringSave="";
featureFilepath ="";
testScaffoldSFilePath="";
var fileStringsInitialized=false;
var generalMapping = new Map();
{
    generalMapping.set("generic",`import pytest_bdd
from conftest import O3_BASE_URL
import string
import random
import time
import re
import pytest
from pytest_bdd import scenarios, given, when, then, parsers
from playwright.sync_api import Page, expect
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'assets'))
from sharedBDDFunctions import *

O3_LOGIN_URL = f'{O3_BASE_URL}/login'
O3_WELCOME_URL = f'{O3_BASE_URL}/login/location'
O3_HOMEPAGE_URL = f'{O3_BASE_URL}/home/service-queues#'

`);
}
var givenMapping = new Map();
{
    givenMapping.set("givenLoginPageDisplayed",`@given("the OpenMRS 3 login page is displayed")
def navigate_to_login(page):
    return navigateToLogin(page)
`);
    givenMapping.set("givenLoggedInto",`@given("logged into OpenMRS O3")
def user_login(page):
    return login(page)
`);
    givenMapping.set("givenTestPatientCreated",`@given("a test patient has been created")
def navigate_to_test_patient(page):
    return navigateToTestPatient(page)
`);
    givenMapping.set("givenEditPatientPageDisplayed",`@given("the OpenMRS 3 edit patient page is displayed")
def verify_test_patient(page):
    return verifyTestPatientExists(page)
`);
}
var thenMapping = new Map();
thenMapping.set("reportCVSS",`@then("Calculate CVSS score")
def calculate_cvss_score():
    return calculateCVSSScore()

`)
var givenThenToFeatureFileMapping = new Map();
{
givenThenToFeatureFileMapping.set("givenLoginPageDisplayed","the OpenMRS 3 login page is displayed");
givenThenToFeatureFileMapping.set("givenLoggedInto","logged into OpenMRS O3");
givenThenToFeatureFileMapping.set("givenTestPatientCreated","a test patient has been created");
givenThenToFeatureFileMapping.set("givenEditPatientPageDisplayed","the OpenMRS 3 edit patient page is displayed");
givenThenToFeatureFileMapping.set("reportCVSS","Calculate CVSS score")
}
function downloadStringAsFile(content, filename, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  
  URL.revokeObjectURL(url); // Clean up memory
}

function generateFeatureFile(filename, when, givenStmts,thenStmts){
    featureFilepath=filename;
    featureFileString="Feature:"+when+"\n";
    featureFileString+="  A description for your feature file\n  Background:\n";
    for(var i = 0;i<givenStmts.length;i++){
        featureFileString+="    Given " + givenThenToFeatureFileMapping.get(givenStmts[i])+"\n";
    }
    featureFileString+="\n  Scenario:"+when + "\n";
    featureFileString+="    When "+when;
    for(var i = 0;i<thenStmts.length;i++){
        featureFileString+="\n    Then " + givenThenToFeatureFileMapping.get(thenStmts[i])+"\n";
    }

    document.querySelector('#featureFile').innerHTML=featureFileString;
}
function generateTemplateFile(){
    var givenStmts = [];
    //see which given statements are needed
    if(document.querySelector('#givenLoginPageDisplayed').checked)givenStmts.push("givenLoginPageDisplayed");
    if(document.querySelector('#givenLoggedInto').checked)givenStmts.push("givenLoggedInto");
    if(document.querySelector('#givenTestPatientCreated').checked)givenStmts.push("givenTestPatientCreated");
    if(document.querySelector('#givenEditPatientPageDisplayed').checked)givenStmts.push("givenEditPatientPageDisplayed");
    console.log("Given clauses:")
    console.log(givenStmts);

    //see which then statements are needed
    var thenStmts = [];
    if(document.querySelector('#reportCVSS').checked)thenStmts.push("reportCVSS");
    console.log("Then clauses:")
    console.log(thenStmts);
    var testScaffold = document.querySelector("#testScaffold")
    var testScaffoldString="";
    testScaffoldString+=generalMapping.get("generic");


    //fill in information needed for scenario file
    var filename = document.querySelector("#testFilenameSTMT").value;
    var featureFileName = document.querySelector("#featureFilenameSTMT").value;
    var location = document.querySelector("#locationSTMT").value;
    var testing = document.querySelector("#testSTMT").value;
    
    testScaffoldSFilePath = filename;

   
    var addCVSSMetrics = false;
    //if calculate cvss, make global variables for that
    for(var i=0;i<thenStmts.length;i++){
        if(thenStmts[i]==="reportCVSS"){
            addCVSSMetrics=true;
        }
    }
    if(addCVSSMetrics){
        //todo
    }
    //paste in mapped given code
    for(var i =0;i<givenStmts.length;i++){
        testScaffoldString+=givenMapping.get(givenStmts[i])
        testScaffoldString+=`
`
    }
    //make scaffolding for the when
    whenString = testing.replaceAll(" ","_")
    whenString = whenString.replaceAll(",","")
    whenString = whenString.replaceAll(":","")
    whenString = whenString.replaceAll(";","")
    whenString = whenString.replaceAll(" ","_")
    testScaffoldString += "@pytest_bdd.scenario('tests/"+location+"/"+featureFileName+".feature','"+testing+"',features_base_dir='')\n";
    testScaffoldString+=`@when('`+testing+`')
def test_`+whenString.replace(" ","_")+`(page:Page):
    #your test code here
    return
`
    
    //past in mapped then code
    for(var i =0;i<thenStmts.length;i++){
        testScaffoldString+=thenMapping.get(thenStmts[i])
        testScaffoldString+=`
`
    }
    testScaffold.innerHTML=testScaffoldString;
    testScaffoldStringSave=testScaffoldString
    generateFeatureFile(featureFileName,testing,givenStmts,thenStmts);
    fileStringsInitialized = true;
}

function downloadFiles(){
    if(fileStringsInitialized){
        downloadStringAsFile(testScaffoldStringSave,"test_"+testScaffoldSFilePath+".py",mimeType='text/plain');
        downloadStringAsFile(featureFileString,featureFilepath+".feature",mimeType='text/plain');
    }
}
