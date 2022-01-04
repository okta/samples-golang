@0
Feature: 0.1 Root page for Direct Auth Demo Application

  Background:
    Given there is existing user named Marie Curie

  @0.1.1
  Scenario: 0.1.1 Marie visits the Root view WITHOUT an authentication session (no tokens)
    Given Marie navigates to the Root view
    Then the Root Page shows links to the Entry Points as defined in https://oktawiki.atlassian.net/l/c/Pw7DVm1t

  @0.1.2
  Scenario: 0.1.2 Marie visits the Root view and WITH an authentication session
    Given Marie navigates to the Root view
    Then she logs in to the application
    And she sees a table with profile info
    And she sees a logout button

  @0.1.3
  Scenario: 0.1.3 Marie logs out of the app
    Given Marie navigates to the Root view
    Then she logs in to the application
    And she sees a table with profile info
    And she sees a logout button
    And she clicks the Logout button
    Then she is logged out
    And she is redirected to the Root view
    And she doesn't see a table with profile info
