# Okta Golang Direct Auth Sample

## Setup

This app modules require the `password_factor` branch github.com/okta/okta-idx-golang .

Therfore, run go get in this fashion before running the app.

```
go env -w GO111MODULE=on
go get github.com/okta/okta-idx-golang@password_factor
```

## Execute

Run the application with the go run command.

```
go run main.go
```

## BDD / Cucumber

The Gherkin format scenarios in `features/` can be run with [godog](https://github.com/cucumber/godog)

```
godog run
```
