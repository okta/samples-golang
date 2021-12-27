@6.1 @no-ci
Feature: 6.1 Multi-Factor Authentication with Password and Email

  Background:
    Given there is a new sign up user named Marie Curie
    And user is added to the org without phone number
    And user is assigned to the group MFA Required

  @6.1.2
  Scenario: 6.1.2 2FA Login with Email
    Given Marie navigates to the Basic Login view
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of enrollment factors
    When she selects Email
    Then she sees a page to input a code
    When she fills in the correct code
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @6.1.3
  Scenario: 6.1.3 Marie enters a wrong verification code
    Given Marie navigates to the Basic Login view
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Email
    Then she sees a page to input a code
    When she fills in the incorrect code
    And she submits the Code form
    Then she sees a message "Invalid code. Try again."
