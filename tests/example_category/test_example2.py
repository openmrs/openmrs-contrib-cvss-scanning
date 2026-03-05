# Test implementation template
# This file represents one scenario in the feature file
# For this test category

import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_BASE_URL

# O3_BASE_URL represents the URL to access OpenMRS 3

# In the scenario decorator, fill out the "tests/"
# string by adding the relevant folder and feature file
# 'tests/<folder>/<feature>.feature'
@pytest_bdd.scenario('tests/',
                     '',
                     features_base_dir='')
def scenario():
    # This function below the decorator represents what will be run
    # when the Scenario is run. The name of the function may be changed
    # but should represent the scenario being called
    pass

# This given is the implementation of the first Given in the background
# It should not be removed. It may be modified to pick the correct CVSS
# metrics for this specific scenario.
@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed():

    # For an indepth reference to CVSS 4.0
    # https://www.first.org/cvss/v4.0/specification-document

    # More CVSS here

    # Calculate CVSS 4.0 score
    cvss_score = calculate_cvss_v4_score(
        AV = BaseMetrics.AttackVector.NETWORK,
        AC = BaseMetrics.AttackComplexity.LOW,
        AT = BaseMetrics.AttackRequirements.NONE,
        PR = BaseMetrics.PriviledgesRequired.NONE,
        UI = BaseMetrics.UserInteraction.NONE,
        VC = BaseMetrics.Confidentiality.VulnerableSystem.NONE,
        VI = BaseMetrics.Integrity.VulnerableSystem.NONE,
        VA = BaseMetrics.Availability.VulnerableSystem.NONE,
        SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE,
        SI = BaseMetrics.Integrity.SubsequentSystem.NONE,
        SA = BaseMetrics.Availability.SubsequentSystem.NONE,
    )

    severity = get_cvss_severity(cvss_score)

    display_results(cvss_score=cvss_score, severity=severity)

# In the given decorator, fill out the parameter as the text of the
# Given statement in Background or the Scenario. For each given in the
# Background and Scenario, a new decorator should be made.
@pytest_bdd.given('')
def given():
    # This function represents what will be run before the When and Then
    # steps. It is to put the system into a known state.
    # If different givens exist, it is important to name the functions
    # differently. This function should be renamed to reflect what the
    # Given's functionality is.
    pass

# In the when decorator, fill out the parameter as the text of the
# When statement in the Scenario. It should be copied and pasted.
@pytest_bdd.when('')
def when():
    # This function represents what will happen during the When step of the scenario.
    pass

# In the when decorator, fill out the parameter as the text of the
# When statement in the Scenario. It should be copied and pasted.
@pytest_bdd.then('')
def then():

    # This function represents what will happen during the Then step of the scenario.
    
    # Calculate results should be called after the last Then has run
    # It will display the CVSS score in the log for the GitHub workflow
    # to pull and use on the dashboard.
    calculate_results()

# Additional then decorators and functions should be added for any
# And and But statements in the feature file, but they should still
# use the @pytest_bdd.then('') format