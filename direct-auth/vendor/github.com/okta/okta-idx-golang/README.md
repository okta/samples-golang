[<img src=".github/images/logo.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![GitHub Workflow Status](https://github.com/okta/okta-idx-golang/workflows/CI/badge.svg)](https://github.com/okta/okta-idx-golang/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/okta/okta-idx-golang?style=flat-square)](https://goreportcard.com/report/github.com/okta/okta-idx-golang)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.14-61CFDD.svg?style=flat-square)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/okta/okta-idx-golang)](https://pkg.go.dev/mod/github.com/okta/okta-idx-golang)

# Okta IDX - Golang

This repository contains the Okta IDX SDK for Golang. This SDK can be used in your server-side code to assist in
authenticating users against the Okta IDX.


> :grey_exclamation: The use of this SDK requires the usage of the Okta Identity Engine. This functionality is in general availability but is being gradually rolled out to customers. If you want to request to gain access to the Okta Identity Engine, please reach out to your account manager. If you do not have an account manager, please reach out to oie@okta.com for more information.

## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                             |
| ------- | ---------------------------------- |
| 0.x     | :warning: In Development           |

The latest release can always be found on the [releases page][github-releases].

## Need help?

If you run into problems using the SDK, you can

- Ask questions on the [Okta Developer Forums][devforum]
- Post [issues on GitHub][github-issues] (for code errors)

## Getting started

### Prerequisites

You will need:

- An Okta account, called an organization. (Sign up for a free [developer organization][developer-edition-signup] if you
  need one)
- Access to the Okta Identity Engine feature. Currently, an early access feature.
  Contact [support@okta.com][support-email] for more information.

## Usage Guide

These examples will help you understand how to use this library.

Once you initialize a `Client`, you can call methods to make requests to the Okta IDX API.

### Create the Client

```go
package main

import (
	"fmt"

	idx "github.com/okta/okta-idx-golang"
)

func main() {
	client, err := idx.NewClient(
		idx.WithClientID("{YOUR_CLIENT_ID}"),
		idx.WithClientSecret("{YOUR_CLIENT_SECRET}"),  // Required for confidential clients.
		idx.WithIssuer("{YOUR_ISSUER}"),               // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
		idx.WithScopes([]string{"openid", "profile"}), // Must include at least `openid`. Include `profile` if you want to do token exchange
		idx.WithRedirectURI("{YOUR_REDIRECT_URI}"),    // Must match the redirect uri in client app settings/console
	)
	if err != nil {
		panic(fmt.Errorf("failed to create a new IDX Client: %v", err))
	}
}
```

#### Password Reset

This example shows step-by-step password reset flow. It includes email verification, answering security question and
setting the password. Note, this might be different in your org depending on the policy settings.

```go
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	idx "github.com/okta/okta-idx-golang"
)

func main() {
	client, err := idx.NewClient()
	if err != nil {
		panic(err)
	}
	up := &idx.IdentifyRequest{
		Identifier: "john.doe@myorg.com",
	}
	resp, err := client.InitPasswordReset(context.TODO(), up)
	if err != nil {
		panic(err)
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.ResetPasswordStepEmailVerification) {
		resp, err = resp.VerifyEmail(context.TODO())
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	reader := bufio.NewReader(os.Stdin)
	if resp.HasStep(idx.ResetPasswordStepEmailConfirmation) {
		fmt.Print("Enter the code from email: ")
		text, _ := reader.ReadString('\n')
		resp, err = resp.ConfirmEmail(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.ResetPasswordStepAnswerSecurityQuestion) {
		fmt.Println(resp.SecurityQuestion().Question)
		text, _ := reader.ReadString('\n')
		resp, err = resp.AnswerSecurityQuestion(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.ResetPasswordStepNewPassword) {
		fmt.Print("Enter new password: ")
		text, _ := reader.ReadString('\n')
		resp, err = resp.SetNewPassword(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.IsAuthenticated() { // same as 'resp.HasStep(idx.ResetPasswordStepSuccess)'
		fmt.Println(resp.Token())
	}
}
```

#### Self Service Registration

This example shows step-by-step Sign Up flow. It includes setting the profile, email verification, setting security
question, phone and the password. Note, this might be different in your org depending on the policy settings.

```go
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	idx "github.com/okta/okta-idx-golang"
)

func main() {
	client, err := idx.NewClient()
	if err != nil {
		panic(err)
	}
	up := &idx.UserProfile{
		LastName:  "John",
		FirstName: "Doe",
		Email:     "john.joe@myorg.com",
	}
	resp, err := client.InitProfileEnroll(context.TODO(), up)
	if err != nil {
		panic(err)
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	reader := bufio.NewReader(os.Stdin)
	if resp.HasStep(idx.EnrollmentStepPasswordSetup) {
		fmt.Print("Enter new password: ")
		text, _ := reader.ReadString('\n')
		resp, err = resp.SetNewPassword(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepEmailVerification) {
		resp, err = resp.VerifyEmail(context.TODO())
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepEmailConfirmation) {
		fmt.Print("Enter the code from email: ")
		text, _ := reader.ReadString('\n')
		resp, err = resp.ConfirmEmail(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepPhoneVerification) {
		fmt.Print("Enter your phone number: ")
		text, _ := reader.ReadString('\n') // e.g. +12346713693
		resp, err = resp.VerifyPhone(context.TODO(), idx.PhoneMethodSMS, text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepPhoneConfirmation) {
		fmt.Print("Enter the code from SMS: ")
		text, _ := reader.ReadString('\n') // e.g. 779419
		resp, err = resp.ConfirmPhone(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepSecurityQuestionOptions) {
		var sq map[string]string
		resp, sq, err = resp.SecurityQuestionOptions(context.TODO())
		if err != nil {
			panic(err)
		}
		fmt.Println("Security Questions: ", sq) // this is the key-valued list of the Security Questions
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepSecurityQuestionSetup) {
		fmt.Print("Enter unique question key: ") // a key from the Security Questions map, e.g. 'disliked_food'
		text, _ := reader.ReadString('\n')
		fmt.Print("Enter the answer: ")
		text2, _ := reader.ReadString('\n')
		resp, err = resp.SetupSecurityQuestion(context.TODO(), &idx.SecurityQuestion{
			QuestionKey: text,
			Answer:      text2,
		})
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.EnrollmentStepSkip) {
		resp, err = resp.Skip(context.TODO())
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.IsAuthenticated() { // same as 'resp.HasStep(idx.EnrollmentStepSuccess)'
		fmt.Println(resp.Token())
	}
}
```

#### Sign In

```go
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	idx "github.com/okta/okta-idx-golang"
)

func main() {
	client, err := idx.NewClient()
	if err != nil {
		panic(err)
	}
	
	resp, err := client.InitLogin(context.TODO())
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(os.Stdin)
	
	// depending on the primary factor in your sign-on policy rule,
	// password may or may not be required to make Identify request
	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.LoginStepIdentifyWithPassword) {
		up := &idx.IdentifyRequest{
			Identifier: "john.joe@myorg.com",
			Credentials: idx.Credentials{},
		}
		fmt.Print("Enter your password: ")
		up.Credentials.Password, _ = reader.ReadString('\n')
		resp, err = resp.Identify(context.TODO(), up)
		if err != nil {
			panic(err)
		}
	} else if resp.HasStep(idx.LoginStepIdentify) {
		up := &idx.IdentifyRequest{
			Identifier: "john.joe@myorg.com",
		}
		resp, err = resp.Identify(context.TODO(), up)
		if err != nil {
			panic(err)
		}
    }

    // if previous step was 'LoginStepIdentifyWithPassword', this step won't appear
    fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.LoginStepPassword) {
		fmt.Print("Enter your password: ")
		text, _ := reader.ReadString('\n')
		resp, err = resp.Password(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.LoginStepEmailVerification) {
		resp, err = resp.VerifyEmail(context.TODO())
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.HasStep(idx.LoginStepEmailConfirmation) {
		fmt.Print("Enter the code from email: ")
		text, _ := reader.ReadString('\n')
		resp, err = resp.ConfirmEmail(context.TODO(), text)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Next steps: ", resp.AvailableSteps())
	if resp.IsAuthenticated() { // same as 'resp.HasStep(idx.LoginStepSuccess)'
		fmt.Println(resp.Token())
	}
}
```

## Configuration Reference

This library looks for the configuration in the following sources:

1. An okta.yaml file in a .okta folder in the current user's home directory (~/.okta/okta.yaml or
   %userprofile%\.okta\okta.yaml)
2. An okta.yaml file in a .okta folder in the application or project's root directory
3. Environment variables
4. Configuration explicitly passed to the constructor (see the example in [Getting started](#getting-started))

Higher numbers win. In other words, configuration passed via the constructor will override configuration found in
environment variables, which will override configuration in okta.yaml (if any), and so on.

### Config Properties

| Yaml Path             | Environment Key       | Description                                                                                                          |
|-----------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------|
| okta.idx.issuer       | OKTA_IDX_ISSUER       | The issuer of the authorization server you want to use for authentication.                                           |
| okta.idx.clientId     | OKTA_IDX_CLIENTID     | The client ID of the Okta Application.                                                                               |
| okta.idx.clientSecret | OKTA_IDX_CLIENTSECRET | The client secret of the Okta Application. Required with confidential clients                                        |
| okta.idx.scopes       | OKTA_IDX_SCOPES       | The scopes requested for the access token.                                                                           |
| okta.idx.redirectUri  | OKTA_IDX_REDIRECTURI  | For most cases, this will not be used, but is still required to supply. You can put any configured redirectUri here. |

#### Yaml Configuration

The configuration could be expressed in our okta.yaml configuration for SDK as follows:

```yaml
okta:
  idx:
    issuer: { issuerUrl }
    clientId: { clientId }
    clientSecret: { clientSecret }
    scopes:
      - { scope1 }
      - { scope2 }
    redirectUri: { configuredRedirectUri }
```

#### Environment Configuration

The configuration could alsp be expressed via environment variables for SDK as follows:

```env
OKTA_IDX_ISSUER
OKTA_IDX_CLIENTID
OKTA_IDX_CLIENTSECRET
OKTA_IDX_SCOPES
OKTA_IDX_REDIRECTURI
```

[okta-library-versioning]: https://developer.okta.com/code/library-versions/

[github-issues]: https://github.com/okta/okta-idx-golang/issues

[developer-edition-signup]: https://developer.okta.com/signup

[support-email]: mailto://support@okta.com