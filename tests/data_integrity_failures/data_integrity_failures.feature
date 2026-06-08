Feature: Data Integrity Failures

    Background:
        Given a CVSS score is calculated and printed

    Scenario: Replace session cookies with another's session
        If a session token can be replaced with another, a compromised session token at one location could give an attacker unrestricted access at another
        Given a clerk account has been logged into and their login token saved
        When another account's login token is replaced with the clerk's
        Then the page shouldn't be logged into the clerk account