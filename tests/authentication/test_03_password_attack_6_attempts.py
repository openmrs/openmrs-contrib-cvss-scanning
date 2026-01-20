import pytest
import pytest_bdd
from selenium.webdriver import Chrome
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

O3_LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
O3_HOME_URL = 'https://o3.openmrs.org/openmrs/spa/home'

@pytest.fixture
def browser():
    driver = Chrome(options=options)
    driver.implicitly_wait(10)
    yield driver
    driver.quit()

@pytest_bdd.scenario('o3_authentication_security.feature', 
                     'Password attack with 6 wrong password attempts',
                     features_base_dir='')
def test_password_attack_6():
    pass

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def navigate_to_login(browser):
    browser.get(O3_LOGIN_URL)
    time.sleep(3)

@pytest_bdd.when('the attacker tries to login with valid username and invalid "password"')
def store_attack_type(browser):
    browser.attack_type = 'password_attack'
    browser.invalid_credential = 'password'
    browser.valid_credential = 'username'
    print("Attack type configured: Password Attack")
    print("Valid: username | Invalid: password")

@pytest_bdd.then(pytest_bdd.parsers.parse(
    'check after {num:d} incorrect attempts, the CVSS score for {attack_name} should be calculated'))
def perform_attack_and_calculate_cvss(browser, num, attack_name):
    AV = 0.85
    PR = 0.85
    UI = 0.85
    S = 0.85
    C = 0.56
    I = 0.56
    A = 0.56
    
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    Impact = 6.42 * ISS
    
    wait = WebDriverWait(browser, 10)
    fail_count = 0
    
    print("")
    print("="*60)
    print("STARTING ATTACK: " + attack_name)
    print("="*60)
    print("Total attempts to perform: " + str(num) + " (wrong passwords)")
    print("Final attempt: 1 (correct credentials)")
    print("-"*60)
    
    # Generate wrong passwords
    wrong_passwords = []
    for i in range(num):
        wrong_passwords.append('wrongpass' + str(i+1))
    
    # PART 1: Perform N incorrect attempts (correct username, wrong password)
    for i, password in enumerate(wrong_passwords, 1):
        print("Attempt " + str(i) + "/" + str(num) + 
              ": username='admin', password='" + password + "'")
        
        time.sleep(2)
        
        username_field = wait.until(EC.presence_of_element_located((By.ID, 'username')))
        username_field.clear()
        username_field.send_keys('admin')
        
        try:
            button = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Continue') or contains(text(), 'Log in')]")))
            button.click()
        except:
            button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.cds--btn--primary")))
            button.click()
        
        time.sleep(3)
        
        try:
            password_field = browser.find_element(By.ID, 'password')
            if password_field.is_displayed():
                password_field.clear()
                password_field.send_keys(password)
                
                login_btn = wait.until(EC.element_to_be_clickable(
                    (By.XPATH, "//button[contains(text(), 'Log in')]")))
                login_btn.click()
                
                time.sleep(3)
        except:
            pass
        
        if O3_HOME_URL in browser.current_url:
            print("  Result: Login SUCCEEDED (unexpected!)")
            break
        else:
            print("  Result: Login FAILED")
            fail_count += 1
            browser.get(O3_LOGIN_URL)
            time.sleep(2)
    
    # PART 2: Attempt correct credentials
    print("")
    print("-"*60)
    print("Now attempting login with CORRECT credentials...")
    print("-"*60)
    
    attempt_number = fail_count + 1
    print("Attempt " + str(attempt_number) + ": username='admin', password='Admin123'")
    
    time.sleep(2)
    
    username_field = wait.until(EC.presence_of_element_located((By.ID, 'username')))
    username_field.clear()
    username_field.send_keys('admin')
    
    try:
        button = wait.until(EC.element_to_be_clickable(
            (By.XPATH, "//button[contains(text(), 'Continue') or contains(text(), 'Log in')]")))
        button.click()
    except:
        button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.cds--btn--primary")))
        button.click()
    
    time.sleep(3)
    
    try:
        password_field = browser.find_element(By.ID, 'password')
        if password_field.is_displayed():
            password_field.clear()
            password_field.send_keys('Admin123')
            
            login_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Log in')]")))
            login_btn.click()
            
            time.sleep(3)
    except:
        pass
    
    final_attempt_blocked = False
    if O3_HOME_URL in browser.current_url:
        print("  Result: Login SUCCEEDED")
    else:
        print("  Result: Login FAILED (System blocked correct credentials)")
        fail_count += 1
        final_attempt_blocked = True
    
    # PART 3: Calculate CVSS
    if final_attempt_blocked:
        AC = 0.44
        security_status = "System blocked ALL attempts (including correct credentials)"
        complexity_level = "HIGH (0.44)"
    elif fail_count >= num:
        AC = 0.77
        security_status = "System allowed " + str(num) + "+ attempts without blocking"
        complexity_level = "LOW (0.77)"
    else:
        AC = 0.44
        security_status = "System blocked after " + str(fail_count) + " attempts"
        complexity_level = "HIGH (0.44)"
    
    Exploitability = 8.22 * AV * AC * PR * UI
    
    if Impact <= 0:
        Base_score = 0
    else:
        Base_score = min((Impact + Exploitability), 10)
        Base_score = round(Base_score, 1)
    
    # PART 4: Display results
    print("")
    print("="*60)
    print("CVSS VULNERABILITY SCORE CALCULATION")
    print("="*60)
    print("Test: " + attack_name)
    print("Security Status: " + security_status)
    print("Attack Complexity: " + complexity_level)
    print("-"*60)
    print("CVSS Base Score: " + str(Base_score))
    print("-"*60)
    print("Total login attempts: " + str(attempt_number))
    print("Failed attempts: " + str(fail_count))
    print("Correct credentials blocked: " + ("YES" if final_attempt_blocked else "NO"))
    print("")
    print("CVSS Metrics:")
    print("  Attack Vector (AV): " + str(AV) + " (Network)")
    print("  Attack Complexity (AC): " + str(AC))
    print("  Privileges Required (PR): " + str(PR) + " (None)")
    print("  User Interaction (UI): " + str(UI) + " (None)")
    print("  Impact Score: " + str(round(Impact, 2)))
    print("  Exploitability Score: " + str(round(Exploitability, 2)))
    print("="*60)
    
    assert Base_score is not None
    assert 0.0 <= Base_score <= 10.0
