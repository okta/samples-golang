@10.1.a @no-ci
Feature: 10.1 TOTP Support (Google Authenticator)

  Background:
    Given configured Authenticators are: "Password (required), Google Authenticator (required)"
    And there is an existing user

  @10.1.a.1
  Scenario: 10.1.1 Mary signs in to an account and enrolls Google Authenticator by scanning a QR Code
    Given Mary is not enrolled in "Google Authenticator"
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Google Authenticator
    And she scans a QR Code
    Then she sees a page to input the code
    When she fills in the correct OTP
    And she submits the code form
    And maybe has to skip
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @10.1.a.2
  Scenario: 10.1.2 Mary signs in to an account and enrolls in Google Authenticator by entering a Secret Key
    Given Mary is not enrolled in "Google Authenticator"
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Google Authenticator
    And she enters the shared Secret Key
    Then she sees a page to input the code
    When she fills in the correct OTP
    And she submits the code form
    And maybe has to skip
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @10.1.a.3
  Scenario: 10.1.3 Mary Signs in to the Sample App with Password and Google Authenticator
    Given Mary navigates to the Basic Login View
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Google Authenticator
    Then sleep 60s
    When she fills in the correct OTP
    And she submits the code form
    And maybe has to skip
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
