@10.1.b @no-ci
Feature: 10.1 TOTP Support (Google Authenticator)

  Background:
    Given configured Authenticators are: "Password (required), Google Authenticator (required)"
    And there is a new sign up user named Mary Acme

  @10.1.b.4
  Scenario: 10.1.4 Mary signs up for an account with Password, setups up required Google Authenticator by scanning a QR Code
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
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

  @10.1.b.5
  Scenario: 10.1.5 Mary signs up for an account with Password, setups up required Google Authenticator by entering a shared secret
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
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
