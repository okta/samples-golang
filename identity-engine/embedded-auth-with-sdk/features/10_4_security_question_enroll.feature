@10.4.a @no-ci @todo
Feature: 10.1 Security Question for Sign Up

  Background:
    Given configured authenticators are: "Password (required), Security Question (required), Email (optional)"
    And there is new user named Marie Curie

  @10.4.a.1
  Scenario: 10.4.1 Marie signs up for an account with Password, setups up predefined Security Question
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new valid email
    And she submits the Registration form
    When fills in new password to enroll
    And she submits the New Password form
    Then she sees a list of enrollment factors
    When she selects Security Question factor
    Then she selects predefined Security Question
    And she fills in the answer
    And she submits the Security Question form
    Then she sees a list of enrollment factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info

  @10.4.a.2
  Scenario: 10.4.2 Marie signs up for an account with Password, setups up custom Security Question
    Given Marie navigates to the Self Service Registration view
    When she fills in new First Name
    And she fills in new Last Name
    And she fills in new valid email
    And she submits the Registration form
    When fills in new password to enroll
    And she submits the New Password form
    Then she sees a list of enrollment factors
    When she selects Security Question factor
    Then she selects custom Security Question
    And she fills in the question
    And she fills in the answer
    And she submits the Security Question form
    Then she sees a list of enrollment factors
    When she selects Email factor
    Then she sees a page to input a code
    When she fills in correct code from email
    And she submits the Code form
    Then she is redirected to the Root view
    And Marie sees a table with profile info
