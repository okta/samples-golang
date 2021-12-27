@10.1.a @no-ci
Feature: 10.1 TOTP Support for Login (Google Authenticator)

  Background:
    Given configured Authenticators are: "Password (required), Google Authenticator (required)"
    And there is an existing user

  @10.1.a.1
  Scenario: 10.1.1 Marie signs in to an account and enrolls Google Authenticator by scanning a QR Code
    Given Marie is not enrolled in "Google Authenticator"
    Given Marie navigates to the Basic Login view
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Google Authenticator
    And she scans a QR Code
    Then she sees a page to input a code
    When she fills in the correct OTP
    And she submits the Code form
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @10.1.a.2
  Scenario: 10.1.2 Marie signs in to an account and enrolls in Google Authenticator by entering a Secret Key
    Given Marie is not enrolled in "Google Authenticator"
    Given Marie navigates to the Basic Login view
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Google Authenticator
    And she enters the shared Secret Key
    Then she sees a page to input a code
    When she fills in the correct OTP
    And she submits the Code form
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @10.1.a.3
  Scenario: 10.1.3 Marie Signs in to the Sample App with Password and Google Authenticator
    Given Marie navigates to the Basic Login view
    Given Marie navigates to the Basic Login view
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Google Authenticator
    Then sleep 60s
    When she fills in the correct OTP
    And she submits the Code form
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info
    And the cell for the value of "email" is shown and contains her email
