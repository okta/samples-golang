/**
 * Copyright 2021 - Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package harness

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/messages-go/v10"
	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/config"
	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/server"
	"github.com/tebeka/selenium"
)

type A18NProfile struct {
	ProfileID    string `json:"profileId"`
	PhoneNumber  string `json:"phoneNumber"`
	EmailAddress string `json:"emailAddress"`
	DisplayName  string `json:"displayName"`
	URL          string `json:"url"`
	Password     string
	GivenName    string
	FamilyName   string
}

type A18NProfiles struct {
	Profiles []A18NProfile `json:"profiles"`
	Count    int           `json:"count"`
}

type TestHarness struct {
	server         *server.Server
	wd             selenium.WebDriver
	capabilities   selenium.Capabilities
	currentProfile *A18NProfile
	httpClient     *http.Client
}

func NewTestHarness() *TestHarness {
	return &TestHarness{
		httpClient: &http.Client{Timeout: time.Second * 60},
	}
}

func (th *TestHarness) InitializeTestSuite(ctx *godog.TestSuiteContext) {
	rand.Seed(time.Now().UnixNano())
	ctx.BeforeSuite(func() {
		cfg := &config.Config{
			Testing: true,
		}
		err := config.ReadConfig(cfg)
		if err != nil {
			log.Fatal(err)
		}

		server := server.NewServer(cfg)
		th.server = server
		server.Run()
	})

	ctx.AfterSuite(func() {
	})
}

func (th *TestHarness) InitializeScenario(ctx *godog.ScenarioContext) {
	debug := os.Getenv("DEBUG")
	if debug != "" {
		val, err := strconv.ParseBool(debug)
		if err == nil {
			selenium.SetDebug(val)
		}
	}

	capabilities := selenium.Capabilities{"browserName": "chrome"}
	capEnv := os.Getenv("SELENIUM_CAPABILITIES")
	if capEnv != "" {
		err := json.Unmarshal([]byte(capEnv), &capabilities)
		if err != nil {
			log.Panic(err)
		}
	}

	seleniumUrl := os.Getenv("SELENIUM_URL")

	// Travis
	inTravis := (os.Getenv("TRAVIS") == "true")
	if inTravis {
		capabilities["tunnel-identifier"] = os.Getenv("TRAVIS_JOB_NUMBER")
		capabilities["build"] = os.Getenv("TRAVIS_BUILD_NUMBER")
		capabilities["tags"] = []string{os.Getenv("TRAVIS_GO_VERSION"), "CI"}
		sauceUsername := os.Getenv("SAUCE_USERNAME")
		sauceAccessKey := os.Getenv("SAUCE_ACCESS_KEY")
		seleniumUrl = fmt.Sprintf("http://%s:%s@ondemand.saucelabs.com/wd/hub", sauceUsername, sauceAccessKey)
	}

	th.capabilities = capabilities

	ctx.BeforeScenario(func(sc *messages.Pickle) {
		th.capabilities["name"] = fmt.Sprintf("Golang (%s / %s) Sample App - %q", os.Getenv("TRAVIS_GO_VERSION"), os.Getenv("TRAVIS_REPO_SLUG"), sc.Name)
		var err error
		th.wd, err = selenium.NewRemote(th.capabilities, seleniumUrl)
		if err != nil {
			log.Panic(err)
		}
	})

	ctx.AfterScenario(func(sc *messages.Pickle, err error) {
		if err != nil {
			fmt.Printf("AfterScenario error: %+v\n", err)
		}

		// always reset the given profile
		err = th.destroyCurrentProfile()
		if err != nil {
			fmt.Printf("AfterScenario error destroying profile: %+v\n", err)
		}

		// always force a logout
		logoutXHR := fmt.Sprintf("var xhr = new XMLHttpRequest(); xhr.open(\"POST\", \"/logout\", false); xhr.send(\"\");")
		_, _ = th.wd.ExecuteScript(logoutXHR, nil)
		err = th.wd.Quit()
		if err != nil {
			fmt.Printf("AfterScenario error quiting web driver: %+v\n", err)
		}
	})

	ctx.Step(`navigates to the Root View`, th.navigateToTheRootView)
	ctx.Step(`Root Page shows links to the Entry Points`, th.checkEntryPoints)
	ctx.Step(`logs in to the Application`, th.loginToApplication)
	ctx.Step(`sees a table with the claims`, th.seesClaimsTable)
	ctx.Step(`doesn't see a table with the claims`, th.doesntSeeClaimsTable)
	ctx.Step(`sees a logout button`, th.seesLogoutButton)
	ctx.Step(`clicks the logout button`, th.clicksLogoutButton)
	ctx.Step(`is logged out`, th.isLoggedOut)
	ctx.Step(`is redirected back to the Root View`, th.isRootView)

	ctx.Step(`navigates to .* Basic Login`, th.navigateToBasicLogin)
	ctx.Step(`fills in (their|her|his) correct username`, th.fillsInUsername)
	ctx.Step(`fills in (their|her|his) incorrect username`, th.fillsInIncorrectUsername)
	ctx.Step(`fills in (their|her|his) password`, th.fillsInPassword)
	ctx.Step(`submits the Login form`, th.submitsLoginForm)
	ctx.Step(`see an error message.*There is no account with the Username`, th.seesNoAccountErrorMessage)
	ctx.Step(`fills in (their|her|his) incorrect password`, th.fillsInIncorrectPassword)
	ctx.Step(`see an error message.*Authentication failed`, th.seesAuthFailedErrorMessage)
	ctx.Step(`clicks on the Forgot Password button`, th.clicksForgotPasswordButton)
	ctx.Step(`is redirected to the Self Service Password Reset View`, th.isPasswordResetView)

	ctx.Step(`there is a new sign up user named ([^"]*)$`, th.createCurrentProfile)
	ctx.Step(`navigates to .* Self Service Registration View`, th.navigateToSelfServiceRegistration)
	ctx.Step(`fills (out|in) (their|her|his) First Name`, th.fillsInSignUpFirstName)
	ctx.Step(`fills (out|in) (their|her|his) Last Name`, th.fillsInSignUpLastName)
	ctx.Step(`fills (out|in) (their|her|his) Email`, th.fillsInSignUpEmail)
	ctx.Step(`submits the registration form`, th.submitsRegistrationForm)
	ctx.Step(`fills (out|in) (their|her|his) Password`, th.fillsInSignUpPassword)
	ctx.Step(`confirms (their|her|his) Password`, th.fillsInSignUpConfirmPassword)
	ctx.Step(`submits the set new password form`, th.submitsNewPasswordForm)
	ctx.Step(`sees a list of required factors to setup`, th.seesSetupListOfRequiredFactors)

	ctx.Step(`navigates to the Password Recovery View`, th.navigatesToThePasswordRecoveryView)
	ctx.Step(`inputs correct Email`, th.inputsCorrectEmail)
	ctx.Step(`submits the recovery form`, th.submitsTheRecoveryForm)
	ctx.Step(`sees a page to input the code`, th.seesPageToInputTheCode)
	ctx.Step(`fills in the correct code`, th.fillsInTheCorrectCode)
	ctx.Step(`submits the code form`, th.submitsTheCodeForm)
	ctx.Step(`sees a page to set new password`, th.seesPageToSetNewPassword)
	ctx.Step(`fills a password that fits within the password policy`, th.fillsPassword)
	ctx.Step(`she submits new password form`, th.submitsNewPassword)
	ctx.Step(`is redirected back to the Root View`, th.isRootView)
	ctx.Step(`inputs incorrect Email`, th.inputsIncorrectEmail)
	ctx.Step(`^she sees a message "([^"]*)"$`, th.noAccountError)
}
