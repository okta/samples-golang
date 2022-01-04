@6.1 @no-ci @fixme
Feature: 6.1 Multi-Factor Authentication with Password and Email

  Background:
    Given there is existing user named Marie Curie
    And app sign-on policy requires two factors
    And configured authenticators are: "Password (required), Email (required)"

  @6.1.2
  Scenario: 6.1.2 2FA Login with Email
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @6.1.3
  Scenario: 6.1.3 Marie enters a wrong verification code
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in incorrect code from email
    And she submits the Code form
    Then she sees "Invalid code. Try again." error message
