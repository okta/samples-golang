Feature: 3.1 Direct Auth Password Recovery

  Scenario: 3.1.1 Mary resets her password
    Given Mary navigates to the Password Recovery View
    When she inputs correct Email
    And she submits the recovery form
    Then she sees a page to input the code
    When she fills in the correct code
    And she submits the code form
    Then she sees a page to set new password
    When she fills a password that fits within the password policy
    And she submits new password form
    Then she is redirected back to the Root View

  Scenario: 3.1.2 Mary tries to reset a password with the wrong email
    Given Mary navigates to the Password Recovery View
    When she inputs incorrect Email
    And she submits the recovery form
    Then she sees a message "There is no account with the Username"
