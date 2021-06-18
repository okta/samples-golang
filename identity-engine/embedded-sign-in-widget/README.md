# Golang + Self Hosted Login Example

## Introduction

> :grey_exclamation: The use of this Sample uses an SDK that requires usage of
the Okta Identity Engine.  This functionality is in general availability but is
being gradually rolled out to customers. If you want to request to gain access
to the Okta Identity Engine, please reach out to your account manager. If you
do not have an account manager, please reach out to oie@okta.com for more
information.

This Sample Application will show you the best practices for integrating
Authentication by embedding the Sign In Widget into your application. The Sign
In Widget is powered by [Okta's Identity
Engine](https://developer.okta.com/docs/concepts/ie-intro/) and will adjust
your user experience based on policies.  Once integrated, you will be able to
utilize all the features of Okta's Sign In Widget in your application.

## Installation & Running The App

This example shows you how to use Golang to login to your application with a
self hosted login page.  The login is achieved with the Okta Sign In Widget,
which gives you more control to customize the login experience within your
app.  After the user authenticates they are redirected back to the
application with an authorization code that is then exchanged for an
access token.


Before running this sample, you will need the following:

* An Okta Developer Account, you can sign up for one at https://developer.okta.com/signup/.

* An Okta Application, configured for Web mode. This is done from the Okta
  Developer Console. When following the wizard, use the default properties. They
  are are designed to work with our sample applications.

## Running This Example

To run this application, you first need to clone this repo and then enter into this directory:

```bash
git clone https://github.com/okta/samples-golang.git
cd samples-golang/identity-engine/embedded-sign-in-widget
```

Then install dependencies:

```bash
go get
```

You also need to gather the following information from the Okta Developer Console:

- **Client ID** and **Client Secret** - These can be found on the "General" tab of the Web application that you created earlier in the Okta Developer Console.
- **Issuer** - This is the URL of the authorization server that will perform authentication.  All Developer Accounts have a "default" authorization server.  The issuer is the scheme and your Org URL without trailing slash. For example, `https://dev-1234.oktapreview.com/oauth2/default`.

The app can find its Okta config variables in `$HOME/.okta/okta.yaml`
and/or it can use the environment variables for the configuration.

When formatting environment variables in a `~/.okta/okta.yaml` file use the
following format.

```yaml
okta:
  idx:
    clientId: {clientId}
    clientSecret: {clientSecret}
    issuer: https://{yourOktaDomain}
    redirectUri: http://localhost:8000/login/callback
    scopes:
      - openid
      - profile
```

When setting environment variables directly in a shell use the following keys.

| Yaml Path             | Environment Key       | Description                                                                  |
|-----------------------|-----------------------|------------------------------------------------------------------------------|
| okta.idx.issuer       | OKTA_IDX_ISSUER       | The issuer of the authorization server used for authentication               |
| okta.idx.clientId     | OKTA_IDX_CLIENTID     | The client ID of the Okta Application.                                       |
| okta.idx.clientSecret | OKTA_IDX_CLIENTSECRET | The client secret of the Okta Application Required with confidential clients |
| okta.idx.scopes       | OKTA_IDX_SCOPES       | The scopes requested for the access token                                    |
| okta.idx.redirectUri  | OKTA_IDX_REDIRECTURI  | The URI to redirect the application to after authentication (optional)       |

Note, the example app attempts to read the `okta.yaml` first first and will then
override any specific values if the corresponding environment variable is found
in the shell.

Now start the app server:

```
go run main.go
```

Now navigate to http://localhost:8000 in your browser.

If you see a home page that prompts you to login, then things are working!  Clicking the **Log in** button will redirect you to the applicaitons custom sign-in page.

You can login with the same account that you created when signing up for your Developer Org, or you can use a known username and password from your Okta Directory.

**Note:** If you are currently using your Developer Console, you already have a Single Sign-On (SSO) session for your Org.  You will be automatically logged into your application as the same user that is using the Developer Console.  You may want to use an incognito tab to test the flow from a blank slate.

[Okta Sign In Widget]: https://github.com/okta/okta-signin-widget
[OIDC WEB Setup Instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application
[viper]: https://github.com/spf13/viper
