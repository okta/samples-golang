Feature: 4.1 Self Service Registration with Email Activation and optional SMS

  Background:
  Given there is a new sign up user named Mary Acme
  # Given a Profile Enrollment policy defined assigning new users to the Everyone Group and by collecting "First Name", "Last Name", and "Email", is allowed and assigned to a SPA, WEB APP or MOBILE application
  # And "Required before access is granted" is selected for Email Verification under Profile Enrollment in Security > Profile Enrollment
  # And configured Authenticators are Password (required), Email (required), and SMS (optional)
  # And a user named "Mary"
  # And Mary does not have an account in the org

  @wip @4.1.1
  Scenario: 4.1.1 Mary signs up for an account with Password, setups up required Email factor, then skips optional SMS
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    # NOTE: sample app doesn't behave like the next 4 lines
    # Then she sees the Select Authenticator page with password as the only option
    # When she chooses password factor option
    # And she submits the select authenticator form
    # Then she sees the set new password form
    When she fills out her Password
    And she confirms her Password
    And she submits the set new password form
    Then she sees a list of required factors to setup
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    Then she sees the list of optional factors (SMS)
    When she selects "Skip" on SMS
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains her first name and last name
