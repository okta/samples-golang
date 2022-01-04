@10.1.b @no-ci @todo
Feature: 10.1 TOTP Support for Enroll (Google Authenticator)

  Background:
    Given configured authenticators are: "Password (required), Google Authenticator (required)"
    And there is new user named Marie Curie

  @10.1.b.4
  Scenario: 10.1.4 Marie signs up for an account with Password, setups up required Google Authenticator by scanning a QR Code
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new valid email
    And she submits the Registration form
    When fills in new password to enroll
    And she submits the New Password form
    Then she sees a list of enrollment factors
    When she selects Google Authenticator factor
    And scans a QR Code with Google Authenticator app
    Then she sees a page to input a code
    When she fills in correct OTP from Google Authenticator app
    And she submits the Code form
    Then she sees a list of enrollment factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @10.1.b.5
  Scenario: 10.1.5 Marie signs up for an account with Password, setups up required Google Authenticator by entering a shared secret
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new valid email
    And she submits the Registration form
    When fills in new password to enroll
    And she submits the New Password form
    Then she sees a list of enrollment factors
    When she selects Google Authenticator factor
    And she enters the shared Secret Key to Google Authenticator app
    Then she sees a page to input a code
    When she fills in correct OTP from Google Authenticator app
    And she submits the Code form
    Then she sees a list of enrollment factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info
