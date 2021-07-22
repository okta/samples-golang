@6.2 @no-ci
Feature: 6.2 Multi-Factor Authentication with Password and SMS

  @6.2.1
  Scenario: 6.2.1 Enroll in SMS Factor prompt when authenticating
    Given there is a new sign up user named Mary Acme
    And user is added to the org without phone number
    And user is assigned to the group Phone Enrollment Required
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Email
    Then she sees a page to input the code
    When she fills in the correct code
    And she submits the code form
    Then she sees a list of factors
    When she selects Phone from the list
    Then she sees form with method and phone number
    When she inputs a method and valid phone number
    Then she sees a page to input the code
    When she inputs the correct code from her SMS
    And she submits the code form
    Then she is redirected back to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @6.2.2
  Scenario: 6.2.2 2FA Login with SMS
    Given there is a new sign up user named Mary Acme
    And user is added to the org with phone number
    And user is assigned to the group MFA Required
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Phone
    Then she sees form with method
    When she inputs a method
    Then she sees a page to input the code
    When she inputs the correct code from her SMS
    And she submits the code form
    Then she is redirected back to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name

  @6.2.3
  Scenario: 6.2.3 Enroll with Invalid Phone Number
    Given there is a new sign up user named Mary Acme
    And user is added to the org without phone number
    And user is assigned to the group Phone Enrollment Required
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Email
    Then she sees a page to input the code
    When she fills in the correct code
    And she submits the code form
    Then she sees a list of factors
    When she selects Phone from the list
    Then she sees form with method and phone number
    When she inputs a method and invalid phone number
    Then she sees a message "Invalid Phone Number."

  @6.2.4
  Scenario: 6.2.4 2FA Mary enters a wrong verification code on verify
    Given there is a new sign up user named Mary Acme
    And user is added to the org with phone number
    And user is assigned to the group MFA Required
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her password
    And she submits the Login form
    Then she sees a list of factors
    When she selects Phone
    Then she sees form with method
    When she inputs a method
    Then she sees a page to input the code
    When fills in the incorrect code
    And she submits the code form
    Then she sees a message "Invalid code. Try again."
