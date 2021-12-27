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
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/config"
	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/server"
	"github.com/tebeka/selenium"
	"github.com/xlzd/gotp"
)

const (
	EmailCodeType = "email"
	SmsCodeType   = "sms"
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
	ErrorDesc    string `json:"errorDescription"`
	KeepProfile  bool
}

type A18NProfiles struct {
	Profiles []A18NProfile `json:"profiles"`
	Count    int           `json:"count"`
}

type A18NContent struct {
	MessageID string    `json:"messageId"`
	ProfileID string    `json:"profileId"`
	CreatedAt time.Time `json:"createdAt"`
	Content   string    `json:"content"`
	URL       string    `json:"url"`
}

type A18NContentEmail struct {
	A18NContent
	ToAddress   string `json:"toAddress"`
	FromAddress string `json:"fromAddress"`
	Subject     string `json:"subject"`
}

type A18NContentSMS struct {
	A18NContent
	Sender   string `json:"sender"`
	Receiver string `json:"receiver"`
}

type TestHarness struct {
	server         *server.Server
	wd             selenium.WebDriver
	capabilities   selenium.Capabilities
	currentProfile *A18NProfile
	appID          string
	httpClient     *http.Client
	oktaClient     *okta.Client
	org            orgData
	googleAuth     *gotp.TOTP
	authenticators authenticators
}

type authenticators struct {
	googleAuth *gotp.TOTP
}

type orgData struct {
	appSignOnPolicy     string
	signOnPolicyRule    string
	mfaRequiredGroupID  string
	everyoneGroupID     string
	mfaEnrollPolicy     string
	mfaEnrollPolicyRule string
}

func NewTestHarness() *TestHarness {
	return &TestHarness{
		httpClient: &http.Client{Timeout: time.Second * 30},
	}
}

func (th *TestHarness) InitializeTestSuite(ctx *godog.TestSuiteContext) {
	rand.Seed(time.Now().UnixNano())
	ctx.BeforeSuite(func() {
		httpClient := &http.Client{Timeout: time.Second * 30}
		httpClient.Transport = &testThrottledTransport{}
		cfg := &config.Config{
			Testing:    true,
			HttpClient: httpClient,
		}
		_, client, err := okta.NewClient(
			context.Background(),
			okta.WithHttpClientPtr(th.httpClient),
			okta.WithCache(false),
		)
		if err != nil {
			log.Fatalf("init test suite new client error: %+v", err)
		}
		srv := server.NewServer(cfg)
		th.server = srv
		th.oktaClient = client

		appName := os.Getenv("OKTA_IDX_APP_NAME")
		if appName == "" {
			appName = "Golang IDX Web App"
		}
		// remove all non-default app sign-on policy rules and reset Catch-all Rule to default settings
		apps, _, err := th.oktaClient.Application.ListApplications(context.Background(), &query.Params{Q: appName})
		if err != nil {
			log.Fatalf("failed to list apps: %+v", err)
		}
		if len(apps) != 1 {
			log.Fatalf("more than one app with name '%s' exists", appName)
		}
		th.appID = apps[0].(*okta.Application).Id

		accessPolicy := linksValue(apps[0].(*okta.Application).Links, "accessPolicy", "href")
		if accessPolicy == "" {
			log.Fatal("app does not support sign-on policy or this feature is not available")
		}
		th.org.appSignOnPolicy = path.Base(accessPolicy)

		// TODO app should be assigned to everyone group

		err = th.resetOrganization(context.Background())
		if err != nil {
			log.Fatalf("failed to setup the organisation: %v", err)
		}

		srv.Run()
	})
	ctx.AfterSuite(func() {
	})
}

func (th *TestHarness) removeTestUsers(ctx context.Context) error {
	users, _, err := th.oktaClient.User.ListUsers(ctx, &query.Params{
		Q:     "Marie",
		Limit: 200,
	})
	if err != nil {
		return err
	}
	for _, u := range users {
		e := *u.Profile
		if !strings.HasSuffix(e["email"].(string), "a18n.help") {
			continue
		}
		// deactivate
		_, err := th.oktaClient.User.DeactivateOrDeleteUser(ctx, u.Id, nil)
		if err != nil {
			return err
		}
		time.Sleep(time.Second)
		// delete
		_, err = th.oktaClient.User.DeactivateOrDeleteUser(ctx, u.Id, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (th *TestHarness) resetOrganization(ctx context.Context) error {
	// clean all the test users
	err := th.removeTestUsers(ctx)
	if err != nil {
		return err
	}
	err = th.deleteAllTestProfiles()
	if err != nil {
		return err
	}
	err = th.deleteProfile(th.currentProfile)
	if err != nil {
		return err
	}
	th.currentProfile = nil

	// remove all sign-on policies, keep default sign-on policy and default sign-on policy rule
	policies, _, err := th.ListPolicies(ctx, &query.Params{Type: "OKTA_SIGN_ON"})
	if err != nil {
		return err
	}
	for i := range policies {
		if policies[i].Name == "Default Policy" {
			rules, _, err := th.oktaClient.Policy.ListPolicyRules(ctx, policies[i].Id)
			if err != nil {
				return err
			}
			for j := range rules {
				if rules[j].Name == "Default Rule" {
					continue
				}
				_, err = th.oktaClient.Policy.DeletePolicyRule(ctx, policies[i].Id, rules[j].Id)
				if err != nil {
					return err
				}
			}
			continue
		}
		_, err := th.oktaClient.Policy.DeletePolicy(ctx, policies[i].Id)
		if err != nil {
			return err
		}
	}

	rules, _, err := th.ListAppSignOnPolicyRules(ctx, th.org.appSignOnPolicy)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.Name == "Catch-all Rule" {
			rule.Actions.AppSignOn.VerificationMethod.FactorMode = "1FA"
			rule.Actions.AppSignOn.VerificationMethod.Type = "ASSURANCE"
			rule.Actions.AppSignOn.VerificationMethod.Constraints = []*okta.AccessPolicyConstraints{
				{
					Knowledge: &okta.KnowledgeConstraint{
						Types: []string{"password"},
					},
				},
			}
			_, _, err = th.UpdateAppSignOnPolicyRule(ctx, th.org.appSignOnPolicy, rule.Id, rule)
			if err != nil {
				return err
			}
			continue
		}
		_, err = th.oktaClient.Policy.DeactivatePolicyRule(ctx, th.org.appSignOnPolicy, rule.Id)
		if err != nil {
			return err
		}
		time.Sleep(time.Second)
		_, err = th.oktaClient.Policy.DeletePolicyRule(ctx, th.org.appSignOnPolicy, rule.Id)
		if err != nil {
			return err
		}

	}

	// remove all non-default MFA enrollment policies and and disable all eligible authenticators in default policy
	mfaPolicies, _, err := th.ListPolicies(ctx, &query.Params{Type: "MFA_ENROLL"})
	if err != nil {
		return err
	}

	authenticators, _, err := th.oktaClient.Authenticator.ListAuthenticators(ctx)
	if err != nil {
		return err
	}
	var pas []PolicySettingsAuthenticator
	for _, authenticator := range authenticators {
		if authenticator.Status == "ACTIVE" && authenticator.Key != "okta_password" {
			pas = append(pas, PolicySettingsAuthenticator{
				Key: authenticator.Key,
				Enroll: PolicySettingsAuthenticatorEnroll{
					Self: "NOT_ALLOWED",
				},
			})
		}
	}

	for _, policy := range mfaPolicies {
		if policy.Name == "Default Policy" {
			policy.Settings.Authenticators = pas
			_, _, err = th.UpdatePolicy(ctx, policy.Id, policy)
			if err != nil {
				return fmt.Errorf("failed to update default policy: %w", err)
			}
			continue
		}
		_, err = th.oktaClient.Policy.DeletePolicy(ctx, policy.Id)
		if err != nil {
			return err
		}
	}

	// disable all authenticators
	for _, authenticator := range authenticators {
		// don't disable email and password
		if authenticator.Key == "okta_email" || authenticator.Key == "okta_password" || authenticator.Status == "INACTIVE" {
			continue
		}
		_, _, err = th.oktaClient.Authenticator.DeactivateAuthenticator(ctx, authenticator.Id)
		if err != nil {
			return fmt.Errorf("failed to deactivate authenticator %s: %w", authenticator.Key, err)
		}
	}
	return nil

	// TODO Reset Default Password policy and policy rule
}

type testThrottledTransport struct{}

func (t *testThrottledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rapid concurrent connections that can be exhibited in an automated test
	// harness can get rate limited.
	// https://developer.okta.com/docs/reference/rl-additional-limits/
	time.Sleep(time.Millisecond * 75)
	return http.DefaultTransport.RoundTrip(req)
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
	inTravis := os.Getenv("TRAVIS") == "true"
	if inTravis {
		capabilities["tunnel-identifier"] = os.Getenv("TRAVIS_JOB_NUMBER")
		capabilities["build"] = os.Getenv("TRAVIS_BUILD_NUMBER")
		capabilities["tags"] = []string{os.Getenv("TRAVIS_GO_VERSION"), "CI"}
		sauceUsername := os.Getenv("SAUCE_USERNAME")
		sauceAccessKey := os.Getenv("SAUCE_ACCESS_KEY")
		seleniumUrl = fmt.Sprintf("http://%s:%s@ondemand.saucelabs.com/wd/hub", sauceUsername, sauceAccessKey)
	}

	th.capabilities = capabilities

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		th.capabilities["name"] = fmt.Sprintf("Golang (%s / %s) Sample App - %q", os.Getenv("TRAVIS_GO_VERSION"), os.Getenv("TRAVIS_REPO_SLUG"), sc.Name)
		var err error
		th.wd, err = selenium.NewRemote(th.capabilities, seleniumUrl)
		if err != nil {
			return ctx, err
		}
		fmt.Println()
		fmt.Println(sc.Name)
		fmt.Println()

		return ctx, nil
	})

	ctx.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if err != nil {
			return ctx, fmt.Errorf("AfterScenario error: %+v\n", err)
		}

		err = th.resetOrganization(context.Background())
		if err != nil {
			log.Fatalf("failed to setup the organisation: %v", err)
		}

		// always force a logout
		logoutXHR := fmt.Sprintf("var xhr = new XMLHttpRequest(); xhr.open(\"POST\", \"/logout\", false); xhr.send(\"\");")
		_, _ = th.wd.ExecuteScript(logoutXHR, nil)
		err = th.wd.Quit()
		if err != nil {
			return ctx, fmt.Errorf("AfterScenario error quiting web driver: %+v\n", err)
		}
		return ctx, nil
	})

	th.steps(ctx)

	ctx.Step(`sleep ([^" ]+)`, th.debugSleep)

	/*ctx.Step(`Root Page shows links to the Entry Points`, th.checkEntryPoints)
	ctx.Step(`logs in to the Application`, th.loginToApplication)
	ctx.Step(`sees a table with the claims`, th.seesClaimsTable)
	ctx.Step(`doesn't see a table with the claims`, th.doesntSeeClaimsTable)
	ctx.Step(`sees a logout button`, th.seesLogoutButton)
	ctx.Step(`is logged out`, th.isLoggedOut)
	ctx.Step(`is redirected back to the Root View`, th.isRootView)

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
	ctx.Step(`user is added to the org ([^"]*) phone number`, th.addUser)
	ctx.Step(`user is assigned to the group ([^"]*)$`, th.addUserToGroup)

	ctx.Step(`fills (out|in) (their|her|his) First Name`, th.fillsInSignUpFirstName)
	ctx.Step(`fills (out|in) (their|her|his) Last Name`, th.fillsInSignUpLastName)
	ctx.Step(`fills (out|in) (their|her|his) Email$`, th.fillsInSignUpEmail)
	ctx.Step(`fills (out|in) (their|her|his) Email with an invalid email format`, th.fillsInInvalidSignUpEmail)
	ctx.Step(`sees an error message "([^"]*)"$`, th.seesErrorMessage)
	ctx.Step(`submits the registration form`, th.submitsRegistrationForm)
	ctx.Step(`fills (out|in) (their|her|his) Password`, th.fillsInSignUpPassword)
	ctx.Step(`confirms (their|her|his) Password`, th.fillsInSignUpConfirmPassword)
	ctx.Step(`submits the set new password form`, th.submitsNewPasswordForm)
	ctx.Step(`sees (a|the) list of (optional|required) factors`, th.waitForEnrollFactorForm)
	ctx.Step(`selects Email`, th.selectsEmail)
	ctx.Step(`selects Phone`, th.selectsPhone)
	ctx.Step(`(he|she) selects "Skip"`, th.clicksSkip)
	ctx.Step(`(he|she) sees a page to input a code`, th.waitForEmailCodeForm)
	ctx.Step(`(he|she) inputs the correct code from (her|his) email`, th.fillsInTheEnrollmentCode)
	ctx.Step(`sees a list of (optional|required) factors`, th.waitForEnrollFactorForm)
	ctx.Step(`is redirected to the Root View`, th.isRootView)
	ctx.Step(`(he|she) sees a table with (her|his) profile info`, th.noop)
	ctx.Step(`the cell for the value of "([^"]*)" is shown`, th.seesClaimsTableItemAndValueFromCurrentProfile)
	ctx.Step(`(he|she) inputs a valid phone number`, th.fillsInTheEnrollmentPhone)
	ctx.Step(`(he|she) inputs an invalid phone number`, th.fillsInInvalidEnrollmentPhone)
	ctx.Step(`(he|she) selects "Receive a Code"`, th.fillsInReceiveSMSCode)
	ctx.Step(`the screen changes to receive an input for a code`, th.waitForEnrollPhoneForm)
	ctx.Step(`(he|she) inputs the correct code from (her|his) SMS`, th.fillsInTheEnrollmentCodeSMS)
	ctx.Step(`(he|she) selects "Verify"`, th.clicksVerifySMSCode)

	// 3.x.x
	ctx.Step(`inputs correct Email`, th.inputsCorrectEmail)
	ctx.Step(`submits the recovery form`, th.submitsTheRecoveryForm)
	ctx.Step(`sees a page to input the code`, th.waitForEmailCodeForm)
	ctx.Step(`fills in the correct code`, th.fillsInTheCorrectCode)
	ctx.Step(`submits the code form`, th.submitsTheCodeForm)
	ctx.Step(`sees a page to set new password`, th.seesPageToSetNewPassword)
	ctx.Step(`fills a password that fits within the password policy`, th.fillsPassword)
	ctx.Step(`she submits new password form`, th.submitsNewPassword)
	ctx.Step(`inputs incorrect Email`, th.inputsIncorrectEmail)
	ctx.Step(`^she sees a message "([^"]*)"$`, th.seesErrorMessage)

	ctx.Step(`fills in the incorrect code`, th.fillsInTheIncorrectCode)
	ctx.Step(`sees a list of factors`, th.factorList)

	ctx.Step(`sees form with method and phone number$`, th.seesPhoneWithMethod)
	ctx.Step(`sees form with method$`, th.seesMethod)
	ctx.Step(`inputs a method$`, th.submitsMethod)
	ctx.Step(`inputs a method and valid phone number$`, th.submitsPhoneWithMethod)
	ctx.Step(`inputs a method and invalid phone number$`, th.submitsInvalidPhoneWithMethod)

	ctx.Step(`user with Facebook account`, th.facebookUser)
	ctx.Step(`she clicks the Login with Facebook button`, th.clicksLoginWithFacebook)
	ctx.Step(`^logs into Facebook$`, th.logsIntoFacebook)
	ctx.Step(`app Sign On Policy MFA Rule has Everyone user's group membership`, th.singOnPolicyRuleGroup)

	ctx.Step(`^configured Authenticators are: "([^"]*)"`, th.configuredAuthenticators)
	ctx.Step(`is not enrolled in "([^"]*)"`, th.isNotEnrolledIn)
	ctx.Step(`scans a QR Code`, th.scansAQRCode)
	ctx.Step(`enters the shared Secret Key`, th.entersTheSharedSecretKey)
	ctx.Step(`selects Google Authenticator`, th.selectsGoogleAuthenticator)
	ctx.Step(`fills in the correct OTP`, th.fillsInTheCorrectOTP)
	ctx.Step(`maybe has to skip`, th.maybeSkip)*/
}
