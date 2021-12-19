@10.1.b @no-ci
Feature: 10.1 TOTP Support (Google Authenticator)

  Background:
    Given configured Authenticators are: "Password (required), Google Authenticator (required)"

  @10.1.b.4
  Scenario: 10.1.4 Mary signs up for an account with Password, setups up required Google Authenticator by scanning a QR Code
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she fills out her Age
    And she submits the registration form
    Then she sees the Select Authenticator page with password as the only option
    When she chooses password factor option
    And she submits the select authenticator form
    Then she sees the set new password form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
    Then she sees a list of required factors to setup
    When She selects Google Authenticator from the list
    And She scans a QR Code
    And She selects "Next"
    Then the screen changes to receive an input for a code
    When She inputs the correct code from her Google Authenticator App
    And She selects "Verify"
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
    And she fills out her Age
    And she submits the registration form
    Then she sees the Select Authenticator page with password as the only option
    When she chooses password factor option
    And she submits the select authenticator form
    Then she sees the set new password form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
    Then she sees a list of required factors to setup
    When She selects Google Authenticator from the list
    And She enters the shared Secret Key into the Google Authenticator App
    And She selects "Next" on the screen which is showing the QR code
    Then the screen changes to receive an input for a code
    When She inputs the correct code from her Google Authenticator App
    And She selects "Verify"
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name
