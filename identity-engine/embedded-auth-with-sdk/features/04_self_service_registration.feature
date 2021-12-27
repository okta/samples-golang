@4 @no-ci
Feature: 4.1 Self Service Registration with Email Activation and optional SMS

  Background:
    Given configured authenticators are: "Password (required), Phone (optional), Email (required)"
    And there is new user named Marie Curie

  @4.1.1
  Scenario: 4.1.1 Marie signs up for an account with Password, setups up required Email factor, then skips optional SMS
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new valid email
    And she submits the Registration form
    When fills in new password to enroll
    And she submits the New Password form
    Then she sees a list of enrollment factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she sees a list of enrollment factors
    When clicks the Skip button
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @4.1.2
  Scenario: 4.1.2 Marie signs up for an account with Password, setups up required Email factor, AND sets up optional SMS
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new valid email
    And she submits the Registration form
    When fills in new password to enroll
    And she submits the New Password form
    Then she sees a list of enrollment factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she sees a list of enrollment factors
    When she selects Phone factor
    And she fills in new valid phone number
    And she submits the New Phone form
    When she selects SMS
    Then she sees a page to input a code
    When she fills in correct code from sms
    And submits the Verify form
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @4.1.3
  Scenario: 4.1.3 Marie signs up with an invalid Email
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new invalid email
    And she submits the Registration form
    Then she sees "'Email' must be in the form of an email address,Provided value for property 'Email' does not match required pattern" error message

  # TODO Fix 500 error when submitting invalid phone
  # @4.1.4
  # Scenario: 4.1.4 Marie signs up for an account with Password, sets up required Email factor, AND sets up optional SMS with an invalid phone number
  #   Given Marie navigates to the Self Service Registration view
  #   When she fills in new First Name
  #   And she fills in new Last Name
  #   And she fills in new valid email
  #   And she submits the Registration form
  #   When fills in new password to enroll
  #   And she submits the New Password form
  #   Then she sees a list of enrollment factors
  #   When she selects Email factor
  #   Then she sees a page to input a code
  #   When she fills in correct code from email
  #   And she submits the Code form
  #   Then she sees a list of enrollment factors
  #   When she selects Phone factor
  #   And she fills in new invalid phone number
  #   And she submits the New Phone form
  #   Then she sees "Unable to initiate factor enrollment: Invalid Phone Number." error message
  #
