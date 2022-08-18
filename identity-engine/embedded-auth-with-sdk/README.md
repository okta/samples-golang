# Okta Golang Direct Auth Sample

## Introduction

> :grey_exclamation: The use of this Sample uses an SDK that requires usage of
the Okta Identity Engine.  This functionality is in general availability but is
being gradually rolled out to customers. If you want to request to gain access
to the Okta Identity Engine, please reach out to your account manager. If you do
not have an account manager, please reach out to oie@okta.com for more
information.

This Sample Application will show you the best practices for integrating
Authentication into your app using [Okta's Identity
Engine](https://developer.okta.com/docs/concepts/ie-intro/). Specifically, this
application will cover some basic needed use cases to get you up and running
quickly with Okta.

These Examples are:

1. Sign In
2. Sign Out
3. Sign Up
4. Sign In/Sign Up with Social Identity Providers
5. Sign In with Multifactor Authentication using Email, Phone, Okta Verify, or Google Authenticator, or combinations of all four.

### Enable CORS (Cross-Origin Resource Sharing)

Your application must be configured to allow your application to make requests to the Okta API using the Okta session cookie. To enable CORS for your application do the following:

- In your [Okta Developer Console], go to **Security > API > Trusted Origins**
- Add your web application’s base URL `http://localhost:8000` with name `localhost` as a **Trusted Origin**.

## Installation & Running The App

Run the application with the go run command.

The application can find its Okta config variables in `$HOME/.okta/okta.yaml`
and/or it can use the environment variables for the configuration.

| Yaml Path             | Environment Key       | Description                                                                  |
|-----------------------|-----------------------|------------------------------------------------------------------------------|
| okta.idx.issuer       | OKTA_IDX_ISSUER       | The issuer of the authorization server used for authentication               |
| okta.idx.clientId     | OKTA_IDX_CLIENTID     | The client ID of the Okta Application.                                       |
| okta.idx.clientSecret | OKTA_IDX_CLIENTSECRET | The client secret of the Okta Application Required with confidential clients |
| okta.idx.scopes       | OKTA_IDX_SCOPES       | The scopes requested for the access token                                    |
| okta.idx.redirectUri  | OKTA_IDX_REDIRECTURI  | The URI to redirect the application to after authentication (optional)       |

```
go run main.go
```

## Design Patterns / Framework specific information

### BDD / Cucumber

The Gherkin format scenarios in `features/` can be run with our
[godog](https://github.com/cucumber/godog) based behavior driven tests harness.

(OSX) First make sure a local Selenium server is available with the chromedriver.

* `brew install selenium-server-standalone`
* `brew install chromedriver`

Next, start Selenium in one shell.

```
$ selenium-server -port 4444

# or, run a selenium server with its jar directly

$ java -jar selenium-server-4.4.0.jar standalone --port 4444
```

Then run the tests in a separate shell.

These environment variables are utilized for the test user in the selenium tests:

* `OKTA_IDX_APP_NAME` - name of the application (default is "Golang IDX Web App")
* `OKTA_IDX_CLAIMS` - Name/value JSON map of claims that will be checked (string)
* `SELENIUM_URL` - The Selenium server's URL (string)
* `DEBUG=true` - Triggers debug loglines from the godog harness to be emitted
* `A18N_API_URL` - REST API URL for receiving MFA verification codes
* `A18N_API_KEY` - REST API Key
* `OKTA_CLIENT_TOKEN` - Token for Okta Public API
* `OKTA_IDX_FACEBOOK_USER_NAME` - email of Facebook registered user
* `OKTA_IDX_FACEBOOK_USER_PASSWORD` - password of Facebook registered user

```
# OKTA_IDX_ISSUER, OKTA_IDX_CLIENTID, OKTA_IDX_CLIENTSECRET,
# OKTA_IDX_SCOPES, OKTA_IDX_REDIRECTURI have been
# exported into the shell or are set in the $HOME/.okta/okta.yaml file

$ SELENIUM_URL="http://127.0.0.1:4444/wd/hub" go test -v

# filter on cucumber tags which scenarios to run
$ SELENIUM_URL="http://127.0.0.1:4444/wd/hub" go test -v --godog.format=pretty --godog.tags=wip
```
