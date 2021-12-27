@10.1.b @no-ci
Feature: 10.1 TOTP Support for Enroll (Google Authenticator)

  Background:
    Given configured Authenticators are: "Password (required), Google Authenticator (required)"
    And there is a new sign up user named Marie Curie

  @10.1.b.4
  Scenario: 10.1.4 Marie signs up for an account with Password, setups up required Google Authenticator by scanning a QR Code
    Given Marie navigates to the Self Service Registration view
    When she fills in her First Name
    And she fills in her Last Name
    And she fills in her Email
    And she submits the Registration form
    When she fills in her Password
    And she confirms her Password
    And she submits the set new password form
    Then she sees a list of factors
    When she selects Google Authenticator
    And she scans a QR Code
    Then she sees a page to input a code
    When she fills in the correct OTP
    And she submits the Code form
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @10.1.b.5
  Scenario: 10.1.5 Marie signs up for an account with Password, setups up required Google Authenticator by entering a shared secret
    Given Marie navigates to the Self Service Registration view
    When she fills in her First Name
    And she fills in her Last Name
    And she fills in her Email
    And she submits the Registration form
    When she fills in her Password
    And she confirms her Password
    And she submits the set new password form
    Then she sees a list of factors
    When she selects Google Authenticator
    And she enters the shared Secret Key
    Then she sees a page to input a code
    When she fills in the correct OTP
    And she submits the Code form
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name
