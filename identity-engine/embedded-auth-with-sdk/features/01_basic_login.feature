@1
Feature: 1.1 Basic Login with Password Factor

  #Background:
  #  Given a SPA, WEB APP or MOBILE Sign On Policy that defines Password as required
  #  And User Enumeration Prevention is set to ENABLED in Security > General 
  #  And the list of Authenticators contains Email and Password
  #  And a User named "Mary" exists, and this user has already setup email and password factors

  # NOTE: this is duplicate of the way that scenario 0.1.2 in features/00_root_page.feature is implemented
  # Scenario: 1.1.1 Mary logs in with a Password
  #   Given Mary navigates to the Basic Login View
  #   When she fills in her correct username
  #   And she fills in her correct password
  #   And she submits the Login form
  #   Then she is redirected to the Root View
  #   And she sees a table with her profile info
  #   And the cell for the value of "email" is shown and contains her email
  #   And the cell for the value of "name" is shown and contains her first name and last name

  @1.1.2
  Scenario: 1.1.2 Mary doesn't know her username
    Given Mary navigates to the Basic Login View
    When she fills in her incorrect username
    And she fills in her password
    And she submits the Login form
    Then she should see an error message on the Login form "There is no account with the Username xxx".

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
