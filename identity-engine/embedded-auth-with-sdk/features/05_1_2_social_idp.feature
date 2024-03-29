@5.2 @no-ci @invalid
Feature: 5.2 Direct Auth Social Login with MFA

  Background:
    Given user with Facebook account

  @5.2.1
  Scenario: 5.2.1 Marie logs in with a social IDP and gets an error message
    Given Marie navigates to the Basic Login view
    When she clicks the Login with Facebook button
    And logs into Facebook
    Then she sees "Multifactor Authentication and Social Identity Providers is not currently supported, Authentication failed." error message
