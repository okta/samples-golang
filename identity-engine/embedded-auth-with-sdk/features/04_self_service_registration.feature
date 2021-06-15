@4 @no-ci
Feature: 4.1 Self Service Registration with Email Activation and optional SMS

  Background:
    Given there is a new sign up user named Mary Acme

  @4.1.1
  Scenario: 4.1.1 Mary signs up for an account with Password, setups up required Email factor, then skips optional SMS
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    # NOTE: sample app doesn't behave like the next 4 lines
    # Then she sees the Select Authenticator page with password as the only option
    # When she chooses password factor option
    # And she submits the select authenticator form
    # Then she sees the set new password form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
    Then she sees a list of required factors to setup
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    Then she sees the list of optional factors (SMS)
    When she selects "Skip" on SMS
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @4.1.2
  Scenario: 4.1.2 Mary signs up for an account with Password, setups up required Email factor, AND sets up optional SMS
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    # NOTE: sample app doesn't behave like the next 4 lines
    # Then she sees the Select Authenticator page with password as the only option
    # When she chooses password factor option
    # And she submits the select authenticator form
    # Then she sees the set new password form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    Then she sees the list of optional factors (SMS)
    When she selects Phone from the list
    And she inputs a valid phone number
    And she selects "Receive a Code"
    Then the screen changes to receive an input for a code
    When she inputs the correct code from her SMS
    And she selects "Verify"
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @4.1.3
  Scenario: 4.1.3 Mary signs up with an invalid Email
	  Given Mary navigates to the Self Service Registration View
	  When she fills out her First Name
	  And she fills out her Last Name
	  And she fills out her Email with an invalid email format
	  And she submits the registration form
	  Then she sees an error message "'Email' must be in the form of an email address,Provided value for property 'Email' does not match required pattern"

  @4.1.4
  Scenario: 4.1.4 Mary signs up for an account with Password, sets up required Email factor, AND sets up optional SMS with an invalid phone number
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    Then she sees the list of optional factors (SMS)
    When she selects Phone from the list
    And she inputs an invalid phone number
    And she selects "Receive a Code"
    Then she sees an error message "Unable to initiate factor enrollment: Invalid Phone Number."
