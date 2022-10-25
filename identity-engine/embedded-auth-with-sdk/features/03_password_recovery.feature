@3 @no-ci
Feature: 3.1 Direct Auth Password Recovery

  Background:
    Given there is existing user named Marie Curie

  @3.1.1 @no-ci @fixme
  Scenario: 3.1.1 Marie resets her password
    Given Marie navigates to the Password Recovery view
    When she fills in correct username to recover
    And she submits the Recovery form
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    When she fills in new password to reset
    And she submits the New Password form
    Then she is redirected to the Root view

  # Note: User Enumeration Prevention should be disabled
  @3.1.2
  Scenario: 3.1.2 Marie tries to reset a password with the wrong email
    Given Marie navigates to the Password Recovery view
    When she fills in incorrect username to recover
    And she submits the Recovery form
    Then she sees "There is no account with the Username wrong_email@example.com." error message
