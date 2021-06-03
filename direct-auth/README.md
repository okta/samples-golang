# Okta Golang Direct Auth Sample

## Setup

This app's modules require the `password_factor` branch
github.com/okta/okta-idx-golang

Therfore, run go get in this fashion before running the app.

```
go env -w GO111MODULE=on
go get github.com/okta/okta-idx-golang@password_factor
```

## Execute

Run the application with the go run command. 

The application can find its Okta config variables in `$HOME/.okta/okta.yaml`.
Or it can use the following environment variables for the configuration.

* `CLIENT_ID` - The Okta application client ID (string)
* `CLIENT_SECRET` - The Okta application client secret (string)
* `ISSUER` - Oauth2 URI to the Okta organization (string) e.g. "https://test123.okta.com/oauth2/"
* `SCOPES` - Oauth scopes, comma separated values (string) e.g. "openid,profile,email,offline_access"
* `REDIRECT_URI` - The URI to redirect the application to after authentication (string)

```
go run main.go
```

## BDD / Cucumber

The Gherkin format scenarios in `features/` can be run with our
[godog](https://github.com/cucumber/godog) based behavior driven tests harness.

First (OSX example) make sure a local Selenium server is available with the
chromedriver.

* `brew install selenium-server-standalone`
* `brew install chromedriver`

Next, start Selenium in one shell.

```
$ selenium-server -port 4444
```

Then run the tests in a separate shell.

Set all of the claim attributes from `/userinfo` that should be checked into a
JSON formated string environment variabled called `CLAIMS`. Also, these
environment variables are utilized for the test user in the selenium tests.

* `USER_NAME` - The test user that the features will be run as (string)
* `PASSWORD` - The test users's password (string)
* `CLAIMS` - Name/value JSON map of claims that will be checked (string)
* `SELENIUM_URL` - The Selenium server's URL (string)
* `DEBUG=true` - Triggers debug loglines from the godog harness to be emitted

```
# CLIENT_ID, CLIENT_SECRET, ISSUER, SCOPES, REDIRECT_URI have been
# exported into the shell or are set in the $HOME/.okta/okta.yaml file

$ export CLAIMS='{"email":"tester@okta.com","email_verified":"","family_name":"Er","given_name":"Test","locale":"en-US","name":"TestEr","preferred_username":"tester@okta.com","sub":"00abcdefghijklmnopqr","updated_at":"","zoneinfo":"America/Los_Angeles"}'

$ USER_NAME=tester@okta.com PASSWORD=abc123 SELENIUM_URL="http://127.0.0.1:4444/wd/hub" go test -v
```
