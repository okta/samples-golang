Feature: 7.1 Direct Auth with Self Hosted Sign In Widget Social Login with 1 Social IDP

  Background:
    Given a user with a Google account

  @7.1.1 @no-ci
  Scenario: 7.1.1 Mary Logs in with Google Social IDP

    Given Mary navigates to Login with Social IDP
    When she clicks the "Sign in with Google" button in the embedded Sign In Widget
    And logs in to Google
    Then she is redirected to the Root View
    And she navigates to the Profile View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name
