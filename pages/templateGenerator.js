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
from test_utils.utils import calculate_cvss_v4_score, get_cvss_severity, BaseMetrics, O3_BASE_URL
from test_utils.sharedBDDFunctions import navigateToLogin

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

function prepareWhenString(location,featureFileName,testing){
    whenString = testing.replaceAll(" ","_")
    whenString = whenString.replaceAll(",","")
    whenString = whenString.replaceAll(":","")
    whenString = whenString.replaceAll(";","")
    whenString = whenString.replaceAll(" ","_")

    r = "";
    r += "@pytest_bdd.scenario('tests/"+location+"/"+featureFileName+".feature','"+testing+"',features_base_dir='')\n";
    r+=`@when('`+testing+`')
def test_`+whenString.replace(" ","_")+`(page:Page):
    #your test code here
    return
`
    return r;
}

function prepareCVSSCode(){
    r="";
    r+=`
@then("Calculate CVSS score")
def calculate_cvss_score():
`
    var AV,AC,AT,PR,UI,VC,VI,VA,SC,SI,SA =0;
    //AV
    if(document.querySelector('#cvssAVP').checked)AV="P";
    if(document.querySelector('#cvssAVL').checked)AV="L";
    if(document.querySelector('#cvssAVA').checked)AV="A";
    if(document.querySelector('#cvssAVN').checked)AV="M";

    //AC
    if(document.querySelector('#cvssACL').checked)AC="L";
    if(document.querySelector('#cvssACH').checked)AC="H";
    //AT
    if(document.querySelector('#cvssATP').checked)AT="P";
    if(document.querySelector('#cvssATN').checked)AT="N";
    //PR
    if(document.querySelector('#cvssPRN').checked)PR="N";
    if(document.querySelector('#cvssPRL').checked)PR="L";
    if(document.querySelector('#cvssPRH').checked)PR="H";

    //UI
    if(document.querySelector('#cvssUIP').checked)UI="P";
    if(document.querySelector('#cvssUIA').checked)UI="A";
    if(document.querySelector('#cvssUIN').checked)UI="N";
    //VC
    if(document.querySelector('#cvssVCN').checked)VC="N";
    if(document.querySelector('#cvssVCL').checked)VC="L";
    if(document.querySelector('#cvssVCH').checked)VC="H";


    //VI
    if(document.querySelector('#cvssVIN').checked)VI="N";
    if(document.querySelector('#cvssVIL').checked)VI="L";
    if(document.querySelector('#cvssVIH').checked)VI="H";
    //VA
    if(document.querySelector('#cvssVAN').checked)VA="N";
    if(document.querySelector('#cvssVAL').checked)VA="L";
    if(document.querySelector('#cvssVAH').checked)VA="H";
    //SC
    if(document.querySelector('#cvssSCN').checked)SC="N";
    if(document.querySelector('#cvssSCL').checked)SC="L";
    if(document.querySelector('#cvssSCH').checked)SC="H";
    //SI
    if(document.querySelector('#cvssSIN').checked)SI="N";
    if(document.querySelector('#cvssSIL').checked)SI="L";
    if(document.querySelector('#cvssSIH').checked)SI="H";
    //SA
    if(document.querySelector('#cvssSAN').checked)SA="N";
    if(document.querySelector('#cvssSAL').checked)SA="L";
    if(document.querySelector('#cvssSAH').checked)SA="H";

    var arr = [AV,AC,AT,PR,UI,VC,VI,VA,SC,SI,SA];
    r+="    cvss_score=calculate_cvss_v4_score(";
    for(var i =0;i<11;i++){
        r+="'"+arr[i]+"',";
    }
    r+=`)
    severity = get_cvss_severity(cvss_score)
    display_results(cvss_score=cvss_score, severity=severity)

`
    return r;
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
    //paste in mapped given code
    for(var i =0;i<givenStmts.length;i++){
        testScaffoldString+=givenMapping.get(givenStmts[i])
        testScaffoldString+=`
`
    }
    //make scaffolding for the when
    whenString = testing.replaceAll(" ","_")
    testScaffoldString += prepareWhenString(location,featureFileName,testing);

    
    //past in mapped then code
    for(var i =0;i<thenStmts.length;i++){
        testScaffoldString+=thenMapping.get(thenStmts[i])
        testScaffoldString+=`
`
    }

    //if calculate cvss, make global variables for that
    if(document.querySelector("#reportCVSS").checked){
        testScaffoldString += prepareCVSSCode();
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

function toggleDivVisibilityByID(id){
    var x = document.getElementById(id);
    if (x.style.display === "none") {
        x.style.display = "block";
    } else {
        x.style.display = "none";
    }
}
