@8
Feature: Basic Login with Embedded Sign In Widget

  Background:
    Given there is an existing user

  @8.1.1
  Scenario: 8.1.1 Mary logs in with a Password
    Given Mary navigates to the Embedded Widget View
    When she fills in her correct username
    And she clicks the "Next" button
    And she selects password factor
    And she fills in her correct password
    And she clicks the "Verify" button
    Then she is redirected to the Root View
    Then she navigates to the Profile View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

