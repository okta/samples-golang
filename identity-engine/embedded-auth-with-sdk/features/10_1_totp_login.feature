@10.1.a
Feature: 10.1 TOTP Support for Login (Google Authenticator)

  Background:
    Given there is existing user named Marie Curie
    # Always enable factors after user creation
    # If the user need to be enrolled in the specific authenticator, do it in a separate step
    And configured authenticators are: "Password (required), Google Authenticator (required)"

  @10.1.a.1
  Scenario: 10.1.1 Marie signs in to an account and enrolls Google Authenticator by scanning a QR Code
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Google Authenticator factor
    And scans a QR Code with Google Authenticator app
    Then she sees a page to input a code
    When she fills in correct OTP from Google Authenticator app
    And she submits the Code form
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @10.1.a.2
  Scenario: 10.1.2 Marie signs in to an account and enrolls in Google Authenticator by entering a Secret Key
    Given Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Google Authenticator factor
    And she enters the shared Secret Key to Google Authenticator app
    Then she sees a page to input a code
    When she fills in correct OTP from Google Authenticator app
    And she submits the Code form
    And maybe has to skip
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @10.1.a.3
  Scenario: 10.1.3 Marie Signs in to the Sample App with Password and Google Authenticator
    Given Marie is enrolled in Google Authenticator
    And app sign-on policy requires two factors
    And Marie navigates to the Basic Login view
    When she fills in correct username to login
    And she fills in correct password to login
    And she submits the Login form
    Then she sees a list of verification factors
    When she selects Google Authenticator factor
    # need to sleep a minute so the factor resets
    Then she sleeps for 60s
    Then she fills in correct OTP from Google Authenticator app
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info
