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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/messages-go/v10"
	"github.com/tebeka/selenium"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"

	"github.com/okta/samples-golang/identity-engine/embedded-sign-in-widget/config"
	"github.com/okta/samples-golang/identity-engine/embedded-sign-in-widget/server"
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
	UserID       string
}

type TestHarness struct {
	server         *server.Server
	wd             selenium.WebDriver
	capabilities   selenium.Capabilities
	currentProfile *A18NProfile
	httpClient     *http.Client
	oktaClient     *okta.Client
	org            orgData
}

type orgData struct {
	policyID           string
	mfaRuleID          string
	mfaRequiredGroupID string
	everyoneGroupID    string
}

func NewTestHarness() *TestHarness {
	return &TestHarness{
		httpClient: &http.Client{Timeout: time.Second * 30},
	}
}

func (th *TestHarness) InitializeTestSuite(ctx *godog.TestSuiteContext) {
	rand.Seed(time.Now().UnixNano())
	ctx.BeforeSuite(func() {
		cfg := &config.Config{
			Testing: true,
		}
		_, client, err := okta.NewClient(
			context.Background(),
			okta.WithHttpClientPtr(th.httpClient),
		)
		if err != nil {
			log.Fatal(err)
		}
		th.oktaClient = client

		srv := server.NewServer(cfg)
		th.server = srv

		th.depopulateMary()

		srv.Run()
	})

	ctx.AfterSuite(func() {
	})
}

func (th *TestHarness) depopulateMary() {
	users, _, _ := th.oktaClient.User.ListUsers(context.Background(), &query.Params{
		Q:     "Mary",
		Limit: 100,
	})
	for _, u := range users {
		e := *u.Profile
		if !strings.HasSuffix(e["email"].(string), "a18n.help") {
			continue
		}
		// deactivate
		th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), u.Id, nil)
		time.Sleep(time.Second)
		// delete
		th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), u.Id, nil)
	}
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

	ctx.Step(`there is an existing user`, th.existingUser)
	ctx.Step(`user with a Google account`, th.googleUser)
	ctx.Step(`user with a Facebook account`, th.facebookUser)
	ctx.Step(`sleep ([^" ]+)`, th.debugSleep)

	ctx.Step(`navigates to Login with Social IDP`, th.navigateToLogin)
	ctx.Step(`navigates to the Embedded Widget View`, th.navigateToLogin)
	ctx.Step(`navigates to the Root View`, th.navigateToTheRootView)
	ctx.Step(`navigates to the Profile View`, th.navigateToProfileView)
	ctx.Step(`fills in (their|her|his) correct username`, th.fillsInUsername)
	ctx.Step(`(he|she) clicks the "Next" button`, th.clicksNextButton)
	ctx.Step(`selects password factor`, th.selectsPasswordFactor)
	ctx.Step(`fills in (their|her|his) correct password`, th.fillsInPassword)
	ctx.Step(`(he|she) clicks the "Verify" button`, th.clicksVerifyButton)
	ctx.Step(`submits the Login form`, th.submitsLoginForm)
	ctx.Step(`is redirected to the Root View`, th.isRootView)
	ctx.Step(`(he|she) sees a table with (her|his) profile info`, th.noop)
	ctx.Step(`the cell for the value of "([^"]*)" is shown`, th.seesClaimsTableItemAndValueFromCurrentProfile)

	ctx.Step(`(he|she) clicks the "Sign in with Google" button`, th.clicksSigninWithGoogle)
	ctx.Step(`(he|she) clicks the "Sign in with Facebook" button`, th.clicksSigninWithFacebook)
	ctx.Step(`logs in to Google`, th.signsInWithGoogle)
	ctx.Step(`logs in to Facebook`, th.signsInWithFacebook)
	ctx.Step(`is redirected back to the Sample App`, th.isRootView)
}
