@1 @no-ci
Feature: 1.1 Basic Login with Password Factor

  Background:
    Given there is existing user named Marie Curie

  @1.1.2
  Scenario: 1.1.2 Marie doesn't know her username
    Given Marie navigates to the Basic Login view
    When she fills in incorrect username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees "There is no account with the Username wrong_email@example.com." error message

  @1.1.3
  Scenario: 1.1.3 Marie doesn't know her password
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in incorrect password to login
    And she submits the Login form
    Then she sees "Authentication failed" error message

  @1.1.8
  Scenario: 1.1.8 Marie clicks on the "Forgot Password Link"
    Given Marie navigates to the Basic Login view
    When she clicks the Forgot Password button
    Then she is redirected to the Password Recovery view
