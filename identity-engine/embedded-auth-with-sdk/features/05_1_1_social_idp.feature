@5.1
Feature: 5.1 Direct Auth Social Login with Facebook Social IDP

  Background:
    Given user with Facebook account
    And routing rule added with Facebook identity provider

  @5.1.1
  Scenario: 5.1.1 Marie Logs in with Social IDP
    Given Marie navigates to the Basic Login view
    When she clicks the Login with Facebook button
    And logs into Facebook
    And Marie sees a table with profile info
