@5.2
Feature: 5.2  Direct Auth Social Login with MFA

  Background:
    Given user with Facebook account
    And app Sign On Policy MFA Rule has Everyone user's group membership

  @5.2.1
  Scenario: 5.2.1 Mary logs in with a social IDP and gets an error message
    Given Mary navigates to the Basic Login View
    When she clicks the Login with Facebook button
    And logs into Facebook
    Then she sees a message "Multifactor Authentication and Social Identity Providers is not currently supported, Authentication failed."
