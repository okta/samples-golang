@10.4.b @no-ci @todo
Feature: 10.4 Security Question for Sign In

  Background:
    Given there is existing user named Marie Curie
    # Always enable factors after user creation
    # If the user need to be enrolled in the specific authenticator, do it in a separate step
    And configured authenticators are: "Password (required), Security Question (required), Email (optional)"

  @10.4.b.3
  Scenario: 10.4.3 Marie signs in to an account and setups up predefined Security Question
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she sees a list of verification factors
    When she selects Security Question factor
    Then she selects predefined Security Question
    And she fills in the answer
    And she submits the Security Question form
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @10.4.b.4
  Scenario: 10.4.4 Marie signs in to an account and setups up custom Security Question
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she sees a list of verification factors
    When she selects Security Question factor
    Then she selects custom Security Question
    And she fills in the question
    And she fills in the answer
    And she submits the Security Question form
    Then she is redirected to the Root view
    And Marie sees a table with profile info
