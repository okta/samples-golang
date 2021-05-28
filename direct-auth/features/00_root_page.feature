Feature: 0.1 Root page for Direct Auth Demo Application

  Background:

  Scenario: 0.1.1 Mary visits the Root View WITHOUT an authentcation session (no tokens)
    Given Mary navigates to the Root View
    Then the Root Page shows links to the Entry Points as defined in https://oktawiki.atlassian.net/l/c/Pw7DVm1t

  Scenario: 0.1.2 Mary visits the Root View and WITH an authentcation session
    Given Mary navigates to the Root View
    Then Mary logs in to the Application
    And Mary sees a table with the claims from the /userinfo response
    And Mary sees a logout button

  Scenario: 0.1.3 Mary logs out of the app
    Given Mary navigates to the Root View
    Then Mary logs in to the Application
    And Mary sees a table with the claims from the /userinfo response
    And Mary clicks the logout button
    Then her access token is revoked
    And her app session is destroyed
    And she is redirected back to the Root View
