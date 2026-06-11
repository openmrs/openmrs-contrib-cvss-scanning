Feature: PR 6094 authentication security event audit logging

  # source_repo: openmrs/openmrs-core
  # source_pr: 6094
  # candidate_risk_id: risk_001
  # candidate_risk_title: Insufficient Security Event Logging for Authentication Actions
  # owasp_category: A09:2025 Security Logging and Alerting Failures
  # cvss_profile: authentication_event_integrity
  # affected_files: api/src/main/java/org/openmrs/event/LoginAttemptEvent.java, api/src/main/java/org/openmrs/event/LogoutEvent.java
  # evidence: New LoginAttemptEvent and LogoutEvent classes added without explicit logging configuration | No evidence of audit trail persistence logic in event implementation files
  # generated_by: openmrs-pr-aware-cvss-generator

  Scenario: Authentication actions should produce observable security audit events
    Given an OpenMRS test instance with security event logging enabled
    And a test user account is available for authentication
    When the test user performs a login attempt
    And the test user performs a logout action
    Then authentication-related security events should be observable in the audit logging output
    And the observed security behavior should be recorded for later CVSS 4.0 scoring
