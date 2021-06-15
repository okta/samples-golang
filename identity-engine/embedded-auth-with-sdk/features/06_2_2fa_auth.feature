Feature: 6.2 Multi-Factor Authentication with Password and SMS

  Scenario: 6.1.2 Enroll in SMS Factor prompt when authenticating
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
