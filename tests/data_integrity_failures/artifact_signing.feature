Feature: Artifact Signing Integrity

  Scenario: OpenMRS modules should have GPG signatures on JFrog
    Given a list of O3 distribution backend modules
    When the JFrog artifact repository is checked
    Then each module should have a visible .asc signature file