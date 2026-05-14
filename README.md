# OpenMRS O3 Security Testing

Automated security tests for OpenMRS 3 with CVSS vulnerability scoring.

## Prerequisites

- Python 3.9+
- Docker (for running local OpenMRS instance)

## Setup

### 1. Clone and set up virtual environment

```bash
git clone https://github.com/openmrs/openmrs-contrib-cvss-scanning.git
cd openmrs-contrib-cvss-scanning

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Playwright browsers

```bash
playwright install chromium
```

### 4. Configure environment

```bash
cp .env.example .env
```

Edit `.env` to change the target OpenMRS instance if needed:

```
# Default targets local Docker instance
O3_BASE_URL=http://localhost/openmrs/spa

# Or target the public demo server
O3_BASE_URL=https://o3.openmrs.org/openmrs/spa
```

### 5. Start OpenMRS (local testing)

For local testing, spin up an OpenMRS 3 Docker instance:

```bash
docker compose up
```

Wait for the container to fully start (this may take a few minutes). The instance will be available at http://localhost/openmrs/spa

## Running Tests

Run all security tests:

```bash
pytest tests/ -v
```

Run specific test categories:

```bash
# Authentication tests only
pytest tests/authentication/ -v

# Session management tests only
pytest tests/session_management/ -v
```

Generate HTML report:

```bash
pytest tests/ -v --html=report.html --json-report --json-report-file=report.json
```

Generate security dashboard:

```bash
pytest tests/ -v --json-report --json-report-file=report.json | tee test_output.log
python scripts/generate_security_dashboard.py
```
This will generate an HTML file named `security_dashboard.html` in the project root.

## Test Structure

```
tests/
├── authentication/           # Authentication security tests
│   ├── conftest.py          # Shared fixtures and URL config
│   ├── test_01_username_enumeration.py
│   ├── test_02_credential_guessing.py
│   └── ...
└── session_management/       # Session management tests
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `O3_BASE_URL` | `http://localhost/openmrs/spa` | Base URL of the OpenMRS O3 instance |
| `CI` | - | Set automatically in CI environments for headless browser mode |


# Test Implementation Guideline

### 1. Introduction

The OpenMRS O3 Security Testing Framework is an automated security testing system designed
to continuously evaluate OpenMRS vulnerabilities using standardized CVSS 4.0 scoring. This
framework enables both security researchers and OpenMRS contributors to write
behavior-driven tests that simulate real-world attacks against the OpenMRS platform,
automatically calculating vulnerability severity scores based on observed system behavior.
Traditional security testing often relies on manual penetration testing or one-time security audits,
which can be time-consuming, inconsistent, and difficult to repeat as the codebase evolves. This
framework addresses these limitations by providing automated, repeatable security tests that run
continuously through GitHub Actions. Each test not only identifies whether a vulnerability exists
but also quantifies its severity using the industry-standard Common Vulnerability Scoring
System (CVSS) version 4.0, making security findings immediately actionable for developers.
Contributors can write tests for various attack scenarios including authentication attacks (brute
force, credential stuffing), authorization bypass attempts, session management vulnerabilities,
injection attacks, and more. The framework automatically tracks CVSS scores over time,
allowing teams to see whether security is improving or degrading as new code is deployed.
Results are visualized through an automatically generated dashboard at cvss-report.openmrs.org,
providing at-a-glance visibility into the platform's security posture.

### 2. Getting Started

#### 2.1 Prerequisites

Before you begin, ensure you have the following installed on your system: Python 3.11 or higher,
Docker and Docker Compose, and Git. You should also have a basic understanding of security
testing concepts and familiarity with command-line interfaces. No deep security expertise is
required, but understanding common web vulnerabilities (such as brute force attacks, session
hijacking, etc.) will help you write more effective tests.

#### 2.2 Repository Structure

The repository is organized into several key directories. The /tests/authentication/ directory
contains test implementation files (.py) and feature files (.feature) that define test scenarios in
human-readable format. The /scripts/ directory holds the dashboard generation script that


processes test results and creates the HTML dashboard. The .github/workflows/ directory
contains the CI/CD automation configuration that runs tests automatically on every commit.
Finally, requirements.txt at the root specifies all Python dependencies needed for the framework.

#### 2.3 Installation and Setup

To set up the framework locally, start by cloning the repository: git clone
https://github.com/openmrs/openmrs-contrib-cvss-scanning.git and navigate into it with cd
openmrs-contrib-cvss-scanning. Install Python dependencies using pip install -r requirements.txt
--break-system-packages (the flag is required for system Python installations). Install Playwright
browsers with python -m playwright install chromium. Start the OpenMRS instance using
Docker Compose: docker compose up -d. Wait for OpenMRS to fully initialize. You can monitor
the startup process with docker compose logs -f and watch for the message indicating the server
has started successfully.

#### 2.4 Verifying Your Setup

Once OpenMRS is running, verify your setup by running an existing test: pytest
tests/authentication/test_01_brute_force_password.py -v -s. The test should execute successfully,
showing detailed output including the attack progression and final CVSS score calculation. If the
test completes without errors and displays a CVSS score (typically 5.5 for this test when
defenses are working), your environment is correctly configured. You can then generate the
dashboard locally by running python scripts/generate_security_dashboard.py and opening the
resulting security_dashboard.html file in your browser to see the test results visualized.

### 3. Framework Architecture

#### 3.1 Component Overview

The framework consists of several integrated components working together to automate security
testing and scoring. Playwright provides browser automation for UI-based tests, allowing tests to
interact with OpenMRS exactly as a real attacker would through the web interface. The
pytest-bdd library enables behavior-driven test structure using the Given-When-Then format,
making tests readable and maintainable. For API-level testing, the requests library sends direct
HTTP requests to REST endpoints, bypassing the UI layer entirely. The CVSS 4.0 calculator
component uses the official MacroVector lookup table to convert observed vulnerabilities into
standardized severity scores. SQLite database stores all historical test results, enabling baseline
tracking and trend analysis. Finally, the dashboard generator processes test results and creates an
HTML visualization showing current scores, improvements over time, and historical trends.


#### 3.2 Test Execution Flow

When a test runs, it follows a specific flow from execution to visualization. First, the test
executes its attack scenario. For example, attempting to login with incorrect credentials multiple
times. During execution, the test carefully observes and records system behavior such as whether
the account gets locked, how long the lockout lasts, and what HTTP response codes are returned.
After the attack completes, dynamic CVSS parameters are determined based on these
observations, if the system blocked the attacker, Confidentiality and Integrity impacts are set to
Low; if the attacker succeeded, they're set to High. The test then calculates the final CVSS score
by passing all parameters (both static and dynamic) to the MacroVector lookup function, which
returns a score between 0.0 and 10.0. Results are immediately saved to the SQLite database,
where the first run establishes a baseline and subsequent runs track changes over time. Finally,
the dashboard generator reads from the database and creates an updated HTML dashboard
showing all test results with their scores, improvements, and trend visualizations.

#### 3.3 From Test to Dashboard

The complete pipeline from running tests to seeing results on the dashboard happens
automatically through GitHub Actions. When code is pushed to the main branch, the workflow
starts by downloading the previous test results database from artifacts (if it exists). It then spins
up an OpenMRS instance in Docker, runs all security tests while capturing detailed output logs,
and processes the results through the dashboard generator. The generator calculates
improvements by comparing current scores against baselines, builds trend data from historical
runs stored in the database, and creates the HTML dashboard with all visualizations. The
workflow then uploads the updated database as an artifact for the next run and deploys the
dashboard to GitHub Pages, making it instantly accessible at cvss-report.openmrs.org. This
entire process runs automatically on every commit, ensuring the security dashboard always
reflects the current state of the codebase.

### 4. Writing Your First Test

#### 4.1 Established Concepts

Security tests in this framework consist of two complementary files that work together. The
feature file uses the .feature extension and contains human-readable test scenarios written in
Gherkin format, describing what the test does in plain language using Given-When-Then
structure. The test implementation file uses the .py extension and contains the actual Python code
that executes the test, defines CVSS parameters, and implements the step definitions referenced
in the feature file. This separation allows non-technical stakeholders to understand what's being


tested by reading the feature file, while developers work with the implementation details in the
Python file.
Feature files follow the behavior-driven development (BDD) pattern where each scenario begins
with a Given statement describing the initial state, continues with When statements describing
the action being tested, and concludes with Then statements verifying the expected outcomes.
Test implementation files are structured with CVSS parameter definitions at the top documenting
the security scoring rationale, followed by the MacroVector lookup function for score
calculation, dynamic parameter detection functions that determine values based on observed
behavior, and finally the pytest-bdd step implementations decorated with @pytest_bdd.given,
@pytest_bdd.when, and @pytest_bdd.then that execute the actual test logic.

#### 4.2 Detailed Conventions - Coming Soon

The detailed methodology for feature file patterns and test structure conventions is currently
being refined by the research team. This section will be updated with comprehensive guidelines
once patterns are finalized, including naming conventions, file organization standards, step
definition best practices, and code structure templates.
For now, refer to existing tests as templates. The file
tests/authentication/test_01_brute_force_password.py demonstrates a complete front end UI test
including browser automation with Playwright, comprehensive CVSS parameter documentation,
dynamic parameter detection based on lockout behavior, and detailed output logging for
debugging. The file tests/authentication/test_02_brute_force_api.py shows how to test the same
attack scenario against the REST API layer using direct HTTP requests instead of browser
automation. The feature file tests/authentication/o3_authentication_security.feature illustrates
proper Gherkin syntax and scenario structure.
Key principles to follow when writing your test: focus on one specific attack scenario per test to
keep tests focused and maintainable, provide clear documentation of CVSS parameters at the top
of your implementation file explaining why each value was chosen, create separate functions for
dynamic parameter detection so the logic is reusable and testable, and include comprehensive
output logging throughout the test execution to aid in debugging and result verification. Full
conventions including detailed naming patterns, file organization requirements, step definition
standards, and code quality guidelines will be documented as the test suite matures and patterns
emerge from real-world usage.


### 5. CVSS Scoring Guidelines

#### 5.1 Established Concepts

This framework uses CVSS 4.0 Base scoring to quantify vulnerability severity on a scale from
0.0 to 10.0, which is then categorized as None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High
(7.0-8.9), or Critical (9.0-10.0). The Base score focuses on the intrinsic characteristics of the
vulnerability itself, not on temporal factors like exploit availability or environmental factors
specific to particular deployments. Each test calculates its score using eleven CVSS parameters
that describe different aspects of the attack, including how the attack is delivered, what
complexity is involved, and what impact it has if successful.
Tests distinguish between static and dynamic parameters to balance methodological rigor with
automated observation. Static parameters are fixed based on the attack scenario itself - for
example, Attack Vector is always set to Network for remote web-based attacks regardless of
whether the attack succeeds or fails. Dynamic parameters are determined at runtime based on
observed system behavior - for instance, Confidentiality Impact depends on whether the system's
defenses actually blocked the attacker from accessing sensitive data. This approach ensures that
CVSS scores reflect both the theoretical attack characteristics and the actual effectiveness of the
deployed defenses.
The framework uses the MacroVector lookup table method specified in CVSS 4.0, which differs
fundamentally from the mathematical formulas used in CVSS 3.1. Instead of multiplying metric
values together, the system groups the eleven parameters into five Equivalence Classes (EQs),
converts these into a five-number key, and looks up the corresponding score from a table of 108
pre-calibrated values. These values were established by security researchers at FIRST.org based
on analysis of thousands of real-world vulnerabilities, making the scores more accurate and
consistent than formula-based approaches. The lookup happens automatically in the
calculate_cvss_v4_score() function, which takes all eleven parameters as input and returns the
final score.

#### 5.2 Parameter Selection Methodology - Coming Soon

The comprehensive methodology for selecting and justifying CVSS parameters is currently
being developed by the research team. This will include decision frameworks, validation criteria,
and detailed guidance on handling edge cases and ambiguous scenarios.
For now, reference existing tests for parameter selection patterns. Review the extensive header
comments in test_01_brute_force_password.py which explain the rationale for each of the eleven
parameters, showing how Attack Vector is set to Network because the attack is remotely


accessible over the internet, why Attack Requirements is dynamic (None if no lockout exists vs
Present if valid username is required to trigger lockout), and how Confidentiality and Integrity
impacts depend on whether the attacker actually gains access or is blocked by defenses. Examine
how dynamic parameters are detected through observation functions like
determine_confidentiality_integrity_impact() which checks whether lockout blocked the attacker
and sets impacts accordingly. Study the calculate_cvss_v4_score() implementation to understand
how the MacroVector lookup converts your chosen parameters into the final score.
Key considerations when designing CVSS scoring for your test: Consider the attack from the
perspective of an actual attacker attempting to exploit the vulnerability, not from the defender's
viewpoint. Base your static parameters on characteristics of the attack scenario itself, not on what
defenses happen to be deployed - for example, if the attack is network-based, set Attack Vector
to Network even if a firewall might block it in some environments. Identify which parameters
could legitimately change based on system behavior you can observe during the test - these are
candidates for dynamic detection. Document your reasoning for each parameter choice clearly in
comments, explaining not just what value you chose but why that value is appropriate for this
specific attack scenario. Remember that parameter selection is a research methodology question
with academic implications, so rigor and justification matter.
Detailed guidelines including parameter selection decision trees, validation frameworks,
methodology for handling uncertainty, and academic justification standards will be added once
the research methodology is formalized and validated through peer review.

### 6. Running Tests

#### 6.1 Running Tests Locally

To run a single test locally, use pytest with the full path to the test file: pytest
tests/authentication/test_01_brute_force_password.py -v -s. The -v flag provides verbose output
showing each test step as it executes, while the -s flag displays print statements in real-time,
which is essential for watching the attack progress and seeing CVSS score calculations. To run
all tests in the authentication directory, use pytest tests/authentication/ -v -s, or to run the entire
test suite use pytest tests/ -v -s. For generating comprehensive reports, add the reporting flags:
pytest tests/ -v -s --html=report.html --self-contained-html --json-report
--json-report-file=report.json. This creates both an HTML report for human readability and a
JSON report that the dashboard generator uses.


#### 6.2 Viewing Test Output

During test execution, the terminal displays real-time progress including detailed attack logs
showing each login attempt, response codes, and system behavior observations. At the end of
each test, you'll see a formatted CVSS score calculation section that displays the final score,
severity rating, all parameter values with explanations, the complete CVSS vector string, and an
overall security assessment. After tests complete, open the HTML report at report.html in your
browser to see a visual summary with test duration, pass/fail status, and captured logs. The JSON
report at report.json contains structured data that the dashboard generator processes.

#### 6.3 Generating the Dashboard Locally

After running tests, generate the dashboard by executing python
scripts/generate_security_dashboard.py. The script will initialize the SQLite database (creating it
if this is the first run), parse test results from the JSON report, save results to the database and set
baselines for first-time tests, enrich results with baseline comparisons and historical trends, and
generate security_dashboard.html. Open the dashboard file in your browser to see the complete
visualization including summary statistics, individual test results with CVSS scores,
improvement metrics compared to baseline, trend sparklines showing score history, and
mouseover tooltips with detailed run history.

#### 6.4 GitHub Actions Workflow

When you push code to the main branch, GitHub Actions automatically runs the complete test
suite. The workflow starts by downloading the previous test results database from artifacts,
which preserves historical data across runs. It spins up an OpenMRS instance using Docker
Compose and waits for it to fully initialize before proceeding. Tests run with full output logging
captured to test_output.log, which includes all CVSS calculations and attack details. The
dashboard generator processes results and creates the HTML dashboard, which is then deployed
to GitHub Pages at cvss-report.openmrs.org. Finally, the updated database is uploaded as an
artifact named test-results-db with 90-day retention, ensuring future runs can track trends and
improvements.

#### 6.5 Debugging Test Issues

If tests fail or produce unexpected results, start by examining the terminal output carefully - the
-v -s flags show exactly where the test failed and what values were observed. Check the
test_output.log file for complete execution traces including all print statements and error
messages. If CVSS scores appear incorrect, verify that dynamic parameters are being set
properly by checking the output of the parameter detection functions. For OpenMRS connection
issues, use docker compose ps to verify containers are running and docker compose logs to check


for OpenMRS startup errors. If tests time out, increase wait times in the test code or check that
your network connection is stable. For database-related errors, ensure test_results.db exists and
has write permissions, or delete it to start fresh if corrupted. If the dashboard doesn't generate,
verify that report.json exists and contains valid data, and check that all Python dependencies are
installed correctly. When debugging in GitHub Actions, check the workflow logs under the
Actions tab - each step's output is available, including the "Run Security Tests" step which shows
all test output.

### 7. Understanding Results

#### 7.1 Dashboard Structure

The security dashboard provides a comprehensive view of all test results organized into clear
sections. At the top, summary cards display key metrics: Total Tests shows how many security
tests are in the suite, Passed and Failed counts indicate test execution status (not security status -
a "passing" test means it executed successfully and calculated a CVSS score), and Duration
shows the total time spent running all tests. Below the summary, the main test results table
presents detailed information for each test including its name, a description of what attack it
simulates, execution status, CVSS score, severity rating, improvement compared to baseline, a
trend sparkline visualization, and execution duration.

#### 7.2 CVSS Severity Levels

CVSS scores are categorized into five severity levels using industry-standard thresholds. Critical
vulnerabilities score 9.0-10.0 and represent severe security issues that should be addressed
immediately - these typically indicate an attacker can gain full system access with minimal
effort. High severity vulnerabilities score 7.0-8.9 and represent serious security concerns
requiring prompt attention, often indicating significant access or impact but with some limiting
factors. Medium severity scores 4.0-6.9 and indicate notable security issues that should be
addressed but may have mitigating factors like required preconditions or limited impact. Low
severity scores 0.1-3.9 and represent minor security concerns with limited exploitability or
minimal impact. A score of exactly 0.0 indicates None - either no vulnerability exists or defenses
completely prevent exploitation.

#### 7.3 Baseline System

The baseline system tracks security improvements over time by establishing a reference point for
comparison. When a test runs for the very first time, its CVSS score is automatically saved as the
baseline in the SQLite database. This baseline represents the initial security state and remains
constant unless manually reset. All subsequent test runs compare their scores against this


baseline to calculate improvement metrics. The baseline is displayed in the dashboard's "CVSS
Score (Baseline)" column, showing both the current run's score and the original baseline score
for reference. This system allows teams to see whether security is improving, degrading, or
remaining stable as code changes are deployed.

#### 7.4 Improvement Metrics

The Improvement column shows how much the current CVSS score has changed compared to
the baseline, using a calculation of baseline minus current score. Positive values displayed in
green with an upward arrow (such as +2.5 ↑) indicate security improvement - the CVSS score
decreased, meaning the system is less vulnerable than the baseline. Negative values displayed in
red with a downward arrow (such as -2.5 ↓) indicate security degradation - the CVSS score
increased, meaning the system is more vulnerable than the baseline. A value of 0.0 with a dash
(0.0 —) displayed in grey indicates no change from baseline. The direction may seem
counterintuitive at first, but remember that lower CVSS scores mean less vulnerability, so when
CVSS goes down, that's a positive improvement worth celebrating.

#### 7.5 Mouseover Tooltip History

Hovering over any improvement value reveals a detailed tooltip showing the last ten test runs
with complete historical context. The tooltip displays a table with three columns: Run number
(with the current run marked by a ◀ symbol), the CVSS score for that run, and the delta from
baseline for that run with color-coded indicators. This allows you to see patterns over time - for
instance, whether scores have been consistently stable, gradually improving, or showing
volatility. The tooltip provides quick answers to questions like "Has this test always scored 5.5 or
did it recently change?" or "Is the current improvement a one-time event or part of a trend?"
without requiring you to query the database directly.

#### 7.6 Trend Sparkline Visualization

The Trend column displays a small line chart (sparkline) showing CVSS score history over the
last twenty test runs, providing at-a-glance visual trend analysis. The Y-axis ranges from 0 to 10
representing the full CVSS scale, while the X-axis shows run sequence from oldest to newest. A
flat horizontal line indicates consistent security - the score hasn't changed over time. A
downward-sloping line shows improving security - CVSS scores decreasing over time as
defenses strengthen. An upward-sloping line reveals degrading security - CVSS scores
increasing as vulnerabilities emerge or defenses weaken. Volatility with ups and downs suggests
inconsistent security or flaky test behavior that may need investigation. If fewer than two runs
exist for a test, the trend column displays "Not enough data" since you need at least two points to
draw a line.


### 8. Contributing Tests

#### 8.1 Before You Start

Before writing a new security test, review the existing test suite to ensure you're not duplicating
work that's already been done. Check the /tests/authentication/ directory and the feature file to
see what attack scenarios are already covered. Verify that your local OpenMRS instance is
running and accessible - you'll need it functional to develop and test your new test. If your test
requires understanding specific CVSS parameters or attack methodologies, familiarize yourself
with the CVSS 4.0 specification available at
https://www.first.org/cvss/v4.0/specification-document. Consider whether your attack scenario
targets the frontend UI, the REST API, or both - this will determine which testing approach to
use.

#### 8.2 Development Workflow

Start by creating a feature branch from main with a descriptive name like
add-session-hijacking-test or test-sql-injection. Write your feature file scenario first using
Given-When-Then format, describing what the test does in plain language that anyone can
understand. Then implement the test file with comprehensive CVSS parameter definitions at the
top, explaining your rationale for each choice. Test your implementation locally multiple times to
ensure it produces consistent, reliable results - security tests should give the same score for the
same system behavior. Verify that your CVSS score makes sense given the attack scenario and
observed defenses - a completely undefended critical vulnerability should score high, while
well-defended attacks should score lower. Document your parameter rationale thoroughly in
comments, as this serves both as justification for reviewers and as guidance for future
contributors.

#### 8.3 Submitting a Pull Request

When your test is ready, commit your changes and push your feature branch to GitHub. Create a
pull request with a clear title describing what attack scenario the test covers, such as "Add
session fixation attack test" or "Test CSRF vulnerability in patient data endpoints". In the PR
description, explain what vulnerability or attack scenario your test evaluates, describe the
expected behavior if defenses are working properly, show example output including the CVSS
score your test produces, explain your rationale for CVSS parameter choices (especially dynamic
ones), and reference any related OpenMRS security issues or documentation. Include at least one
complete test run output showing the attack progression and final score calculation so reviewers
can see exactly what the test does.


#### 8.4 Review Process

Submitted tests undergo review for both technical correctness and methodological soundness.
Reviewers verify that tests execute reliably and produce consistent results across multiple runs,
checking that CVSS parameters are justified and appropriate for the attack scenario. The
dynamic parameter detection logic is examined to ensure it correctly interprets system behavior.
Tests must pass in the GitHub Actions CI/CD environment, not just locally. Code quality is
assessed including readability, documentation completeness, and adherence to existing patterns.
Finally, security assessment accuracy is validated - does the test actually reveal a real
vulnerability, and does the CVSS score appropriately reflect its severity? Once approved by
project maintainers, your test will be merged and will begin running automatically on every
commit.

#### 8.5 Testing Checklist

Before submitting your PR, verify the following items. Confirm your feature file follows
Given-When-Then structure with clear, readable scenarios. Ensure CVSS parameters are
documented at the top of your test file with detailed rationale explaining each choice. Verify your
test produces consistent results when run multiple times against the same OpenMRS instance.
Check that dynamic parameters detect system behavior correctly - test both with and without
defenses if possible to verify the parameters change appropriately. Include comprehensive output
logging throughout test execution so that anyone debugging can follow the attack flow. Confirm
the test passes both locally and in GitHub Actions CI/CD. Review your code for clarity and
documentation - another developer should be able to understand what your test does and why.
Finally, ensure your git commits are clean with meaningful commit messages and that you've
included all necessary files in your branch.

### 9. Troubleshooting

#### 9.1 Common Issues and Solutions

If OpenMRS fails to start, first check that Docker is running properly with docker ps and verify
that no other services are using the required ports (typically 80 and 3306). Try stopping all
containers with docker compose down and restarting with docker compose up -d, then monitor
the logs with docker compose logs -f to watch for error messages during startup. If tests
consistently time out, the issue may be slow network connections or insufficient system
resources - try increasing wait times in the test code or allocating more memory to Docker. When
CVSS scores show as 0.0, verify that the score calculation function actually executed by
checking the test output logs, and confirm that dynamic parameters were set to valid values
rather than remaining None. Database errors typically indicate permission issues or corruption -


check that test_results.db exists in the repository root and has write permissions, or delete the file
entirely to start fresh if it's corrupted. If the dashboard fails to generate, ensure report.json exists
and contains valid JSON by opening it in a text editor, verify all Python dependencies are
installed with pip install -r requirements.txt --break-system-packages, and check the dashboard
generator output for specific error messages. When GitHub Actions workflows fail, examine the
workflow logs carefully under the Actions tab - look specifically at the "Run Security Tests" and
"Extract CVSS Scores and Generate Dashboard" steps for detailed error messages.

#### 9.2 Where to Get Help

For technical issues with the testing framework itself, start by reviewing existing GitHub Issues
in the repository to see if others have encountered the same problem and found solutions. Check
the test output logs carefully as they often contain specific error messages that point to the root
cause. If you're stuck, open a new GitHub Issue with a clear description of the problem, steps to
reproduce it, relevant log output, and what you've already tried. For questions about OpenMRS
itself rather than the testing framework - such as how specific OpenMRS features work or
expected behavior - consult the OpenMRS Talk community forum at talk.openmrs.org where
OpenMRS developers and users can provide guidance. For CVSS scoring methodology
questions or clarification on parameter selection, reference the official CVSS 4.0 specification at
https://www.first.org/cvss/v4.0/specification-document or contact the project maintainers for
research methodology discussions.

#### 9.3 Useful Debugging Commands

Several commands are particularly helpful when debugging test issues. Use docker compose ps
to check the status of all containers and verify they're running. Run docker compose logs to view
all OpenMRS logs, or add -f flag to follow logs in real-time as they're generated. Execute pytest
--collect-only to list all discoverable tests without running them, which helps verify pytest can
find your test files. Query the test history database directly with sqlite3 test_results.db "SELECT
* FROM history ORDER BY run_at DESC LIMIT 10" to see the last ten test runs, or use sqlite
test_results.db "SELECT * FROM baselines" to check baseline scores. For viewing database
schema, run sqlite3 test_results.db ".schema". To completely reset the test history and start fresh,
simply delete test_results.db and it will be recreated on the next test run. When debugging
Playwright browser automation issues, add browser.pause() in your test code to pause execution
and manually inspect the browser state, or set headless=False in the browser launch
configuration to watch the browser automation in real-time.


### 10. Step-by-Step Technical Guidance

#### 10.1 Choosing Your Attack Scenario

Before writing any code, clearly define what you're testing. For this tutorial, we'll walk through
creating the brute force password attack test. The attack scenario is: an attacker knows the
username "admin" (OpenMRS default username) and tries multiple random passwords to gain
access. We want to test whether OpenMRS blocks the account after several failed attempts and
enforces a cooldown period. This scenario targets the frontend login UI and will help us
understand if the system has proper rate limiting defenses.

##### Step 1: Write the Feature File Scenario

Start by creating or editing the feature file at
tests/authentication/o3_authentication_security.feature. Add your scenario using
Given-When-Then format. The Given statement describes the initial state: "Given the OpenMRS
3 login page is displayed". The When statement describes the attack action: "When the attacker
tries to login with known username 'admin' and random passwords". The Then statements
describe what we verify: "Then check after 7 incorrect attempts, the CVSS score for brute force
password attack should be calculated", followed by "And verify account lockout triggers after 7
failures" and "And verify account becomes accessible after 5-minute cooldown period". This
feature file describes what happens without implementation details, making it readable for
non-technical stakeholders.

##### Step 2: Create the Test File and Define CVSS Parameters

Create a new file tests/authentication/test_01_brute_force_password.py and start with imports.
You'll need pytest_bdd for the BDD framework, conftest for the O3_BASE_URL constant, string
and random for generating random passwords, and time for handling waits. At the top of the file,
define all your CVSS parameters with detailed comments explaining each choice. For this brute
force attack, set static parameters: Attack Vector is Network (anyone on internet can access the
login page), Attack Complexity is Low (straightforward repeated login attempts), Privileges
Required is None (testing the login endpoint itself), and User Interaction is None (fully
automated). Mark dynamic parameters as None initially: Attack Requirements will be
determined based on lockout behavior, Confidentiality Impact and Integrity Impact depend on
whether lockout blocks the attacker, and Availability Impact depends on lockout duration. Set
Subsequent System impacts all to None since this attack only affects OpenMRS itself.

##### Step 3: Implement the MacroVector Lookup Function

Copy the complete calculate_cvss_v4_score() function that implements the CVSS 4.
MacroVector lookup table. This function takes all eleven parameters as input and returns a score


between 0.0 and 10.0. The implementation calculates five Equivalence Class (EQ) values by
grouping the parameters: EQ1 from Attack Vector, Privileges Required, and User Interaction;
EQ2 from Attack Complexity and Attack Requirements; EQ3 from Confidentiality, Integrity, and
Availability impacts; EQ4 from Subsequent System impacts; and EQ5 defaulting to worst case. It
then combines EQ3 and EQ6 using a mapping table, creates a five-number key, looks it up in the
108-entry lookup table, and returns the corresponding score. You don't need to modify this
function - just include it exactly as shown in the existing brute force test.

##### Step 4: Create Dynamic Parameter Detection Functions

Write three functions to determine dynamic parameters based on observed behavior. The
determine_attack_requirements() function checks if lockout was detected - if yes, return 'P' for
Present (attacker must know valid username to trigger lockout), if no, return 'N' for None. The
determine_confidentiality_integrity_impact() function checks if lockout blocked the attacker - if
yes, return 'L', 'L' (Low impact since attacker was blocked), if no, return 'H', 'H' (High impact
since attacker can access all data). The determine_availability_impact() function checks lockout
duration - if no lockout, return 'N', if lockout lasted 1-10 minutes return 'L', if over 10 minutes
return 'H'. These functions encapsulate the decision logic for converting observed system
behavior into CVSS parameters.

##### Step 5: Implement the Test Steps

Now implement the pytest-bdd step functions. The @pytest_bdd.given step navigates to the
login page. The @pytest_bdd.when step performs the actual attack: generate seven random
passwords, loop through each one attempting to login by filling the username field with "admin",
clicking Continue, filling the password field with the random password, clicking Submit, and
checking if login failed. Store all observations in browser.test_results dictionary including
whether rate limiting was detected and when lockout occurred. The first @pytest_bdd.then step
verifies lockout by attempting login with correct credentials (admin/Admin123) - if login still
fails, lockout is working. The final @pytest_bdd.then step tests the cooldown period by waiting
five minutes, attempting login with correct credentials every 30 seconds, and measuring the
actual time until the account unlocks.

##### Step 6: Calculate and Display CVSS Score

At the end of the cooldown verification step, call your dynamic parameter detection functions to
get AT, VC, VI, and VA values based on what you observed during the test. Pass all eleven
parameters (both static and dynamic) to calculate_cvss_v4_score() to get the final score.
Determine the severity rating: 9.0+ is Critical, 7.0-8.9 is High, 4.0-6.9 is Medium, below 4.0 is
Low. Print a comprehensive results section showing the attack name, observed behaviors
(lockout working or not, cooldown working or not), the CVSS Base Score and severity rating, all
parameter values with explanations, and the complete CVSS vector string in the format


CVSS:4.0/AV:N/AC:L/AT:P/.... This output helps both during development for debugging and in
production for understanding why a particular score was assigned.

##### Step 7: Run and Verify Your Test

Run your test locally with pytest tests/authentication/test_01_brute_force_password.py -v -s and
watch the output carefully. You should see the attack configuration printed first, then each of the
seven login attempts showing "Login FAILED (expected)", followed by lockout verification
showing "Account lockout triggered after 7 failures", then the five-minute countdown with
periodic status updates, and finally the CVSS calculation section. The test should complete
successfully and display a score around 5.5 MEDIUM if lockout is working properly. If you get
different results, check that OpenMRS is running, verify your dynamic parameter detection
functions are being called, and examine the browser.test_results dictionary values. Run the test
multiple times to ensure consistency - the same system behavior should produce the same CVSS
score every time.

##### Step 8: Integrate with Dashboard

After your test passes locally, commit your changes and push to GitHub. The GitHub Actions
workflow will automatically run your test, save results to the SQLite database, and regenerate the
dashboard. On the first run, your test's score becomes the baseline. On subsequent runs, the
dashboard will show improvements relative to this baseline. Check the deployed dashboard at
cvss-report.openmrs.org to verify your test appears in the results table with its score, severity
badge, improvement metric (0.0 on first run), and trend line (shows "Not enough data" until you
have at least two runs). The complete integration means your security test is now part of
continuous monitoring - every code change to OpenMRS will run your test and track whether
security improves or degrades over time.


# Detailed File Creation


# Detailed File Creation Guide

Steps to make a test

1. Option 1: Manual Creation
    1. Create a new subfolder, feature file, __init__.py file, and test file
    2. For the test, import pytest_bdd, and from tests.utils import
       calculate_cvss_v4_score, get_cvss_severity, BaseMetrics, O3_BASE_URL
2. Option 2: Use template generator (Not merged yet)
    1. Go to the template generator page
    1. Fill in options listen
    1. ...
    1. This will create all necessary files
3. Write a feature file. The feature file covers all subtests using the same “given.” It will
    contain the following.
       1. Feature: This is the feature of OpenMRS that is going to be tested
       1. Background: This is where shared “givens” between all “scenarios” will be stored.
       1. Given: This is what is given for the test to run. For example, “The login page is
          shown.”
       1. Scenario: This is a specific attack method. Each “scenario” can be converted into
          a test file.
           1. When: The attacker tries some attack method,
           1. Then: The system should do this in response.
           1. And: The system may optionally do this. Any amount of “And’s” may be
used.
5. Every test will need the following structure:
    1. @pytest_bdd.scenario('tests/<subfolder>/<feature file>',
       '<Scenario text of one scenario in feature file>',
       features_base_dir='') followed by a function. def <function name>():
    1. @pytest_bdd.given('<given text>') followed by a function. def <function name>():
    1. @pytest_bdd.when('<when text>') followed by a function. def <function name>():
    1. @pytest_bdd.then('<then text>') followed by a function. def <function name>():
       1. Repeat this for “ands” as well, still using @pytest_bdd.then('<and text>')
    1. A section to calculate CVSS scores.
       1. Define these based on the CVSS 4.0 calculator. They should be static.
       2. Use the function calculate_cvss_v4_score() with parameters using Enums listed in the util.py file
       3. 1. Use get_cvss_severity(cvss_score) to get the severity, in english, of the test.
    1. Display the results (CVSS score, severity, and pass/fail)
5. For each test, fill in each function.
6. Connect the function to the workflow.



