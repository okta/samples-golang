@5.1
Feature: 5.1 Direct Auth Social Login with Facebook Social IDP

  Background:
    Given user with Facebook account

  @5.1.1
  Scenario: 5.1.1 Mary Logs in with Social IDP
    Given Mary navigates to the Basic Login View
    When she clicks the Login with Facebook button
    And logs into Facebook
    Then she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name
