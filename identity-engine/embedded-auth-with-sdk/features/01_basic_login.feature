@1
Feature: 1.1 Basic Login with Password Factor

  Background:
    Given there is an existing user

  @1.1.2
  Scenario: 1.1.2 Mary doesn't know her username
    Given Mary navigates to the Basic Login View
    When she fills in her incorrect username
    And she fills in her password
    And she submits the Login form
    Then she should see an error message on the Login form "Authentication failed".

  @1.1.3
  Scenario: 1.1.3 Mary doesn't know her password
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her incorrect password
    And she submits the Login form
    Then she should see an error message "Authentication failed"

  @1.1.8
  Scenario: 1.1.8 Mary clicks on the "Forgot Password Link"
    Given Mary navigates to the Basic Login View
    When she clicks on the Forgot Password button
    Then she is redirected to the Self Service Password Reset View
