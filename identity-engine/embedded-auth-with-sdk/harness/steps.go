package harness

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"net/url"
	"os"
	"strings"

	"github.com/okta/okta-sdk-golang/v2/okta/query"

	"github.com/cucumber/godog"
	"github.com/liyue201/goqr"
	idx "github.com/okta/okta-idx-golang"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/tebeka/selenium"
	"github.com/xlzd/gotp"
)

func (th *TestHarness) steps(ctx *godog.ScenarioContext) {

	// Scenario Steps
	ctx.Step(`(sees|doesn't see) a table with profile info`, th.profile)
	ctx.Step(`clicks the (Logout|Forgot Password|Login with Facebook|Skip) button`, th.clicksOnButton)
	ctx.Step(`fills in (correct|incorrect) (username|password) to (login|recover)`, th.fillsInCredentials)
	ctx.Step(`fills in (correct|incorrect) code from (email|sms)`, th.fillsInTheCode)
	ctx.Step(`fills in (correct|incorrect) OTP from (Google Authenticator|WebAuthN)`, th.fillsInOTP)
	ctx.Step(`fills in new (First Name|Last Name)`, th.fillsInIdentity)
	ctx.Step(`fills in new (valid|invalid) (email|phone number)`, th.fillsInNewEmailOrPhoneNumber)
	ctx.Step(`fills in new password to (reset|enroll)`, th.fillsNewPassword)
	ctx.Step(`is logged out`, th.isLoggedOut)
	ctx.Step(`is redirected to the (Root|Password Recovery) view`, th.redirected)
	ctx.Step(`logs in to the application`, th.loginToApplication)
	ctx.Step(`navigates to the (Basic Login|Password Recovery|Root|Self Service Registration) view`, th.navigateToTheView)
	ctx.Step(`Root Page shows links to the Entry Points`, th.checkEntryPoints)
	ctx.Step(`scans a QR Code`, th.scansAQRCode)
	ctx.Step(`sees "([^"]*)" error message`, th.seesErrorMessage)
	ctx.Step(`sees a list of (enrollment|verification) factors`, th.listOfFactors)
	ctx.Step(`sees a logout button`, th.seesLogoutButton)
	ctx.Step(`sees a page to input a code`, th.code)
	ctx.Step(`selects (Email|Phone) factor`, th.selectsFactor)
	ctx.Step(`submits the (Login|Recovery|New Password|Registration|Code|New Phone|Verify) form`, th.submitsTheForm)
	ctx.Step(`she selects SMS`, th.selectSMS)
	ctx.Step(`^logs into Facebook$`, th.logsIntoFacebook)

	// Background
	ctx.Step(`there is (existing|new) user named ([^"]*)$`, th.user)
	ctx.Step(`^configured authenticators are: "([^"]*)"`, th.configuredAuthenticators)
	ctx.Step(`user with Facebook account`, th.facebookUser)
	ctx.Step(`routing rule added with (Facebook|some other) identity provider`, th.routingRule)
}

// for now only FACEBOOK is supported
func (th *TestHarness) routingRule(provider string) error {
	var providerID string
	providers, _, err := th.oktaClient.IdentityProvider.ListIdentityProviders(context.TODO(), nil)
	if err != nil {
		return fmt.Errorf("failed to list identity providers: %w", err)
	}
	for _, provider := range providers {
		if provider.Type != "FACEBOOK" {
			continue
		}
		providerID = provider.Id
		break
	}
	if providerID == "" {
		return errors.New("Facebook identity provider is not configured")
	}
	rule := IdpDiscoveryRule{
		Actions: &IdpDiscoveryRuleActions{
			IDP: &IdpDiscoveryRuleIdp{
				Providers: []*IdpDiscoveryRuleProvider{
					{
						Type: "OKTA",
					},
					{
						ID: providerID,
					},
				},
			},
		},
		Conditions: &IdpDiscoveryRuleConditions{
			App: &IdpDiscoveryRuleApp{
				Include: []*IdpDiscoveryRuleAppObj{
					{
						Type: "APP",
						ID:   th.appID,
					},
				},
			},
			Network: &IdpDiscoveryRuleNetwork{
				Connection: "ANYWHERE",
			},
			Platform: &IdpDiscoveryRulePlatform{
				Include: []*IdpDiscoveryRulePlatformInclude{
					{
						Os: &IdpDiscoveryRulePlatformOS{
							Type: "ANY",
						},
						Type: "ANY",
					},
				},
			},
		},
		Name:        "Social IDP",
		Type:        "IDP_DISCOVERY",
		MultiIdpIds: true,
	}
	activate := true
	_, _, err = th.CreateIdpDiscoveryRule(context.TODO(), th.org.idpDiscoveryPolicyID, rule, &query.Params{Activate: &activate})
	if err != nil {
		return fmt.Errorf("failed to create IdP discovery/routing rule: %w", err)
	}
	return nil
}

func (th *TestHarness) facebookUser() error {
	th.currentProfile = &A18NProfile{
		EmailAddress: os.Getenv("OKTA_IDX_FACEBOOK_USER_NAME"),
		Password:     os.Getenv("OKTA_IDX_FACEBOOK_USER_PASSWORD"),
		GivenName:    "Golang",
		FamilyName:   "User",
		DisplayName:  "Golang SDK Test User",
	}
	return nil
}

func (th *TestHarness) addUser(condition string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	profile := okta.UserProfile{}
	profile["firstName"] = th.currentProfile.GivenName
	profile["lastName"] = th.currentProfile.FamilyName
	profile["login"] = th.currentProfile.EmailAddress
	profile["email"] = th.currentProfile.EmailAddress
	if condition == "with" {
		profile["mobilePhone"] = th.currentProfile.PhoneNumber
		profile["primaryPhone"] = th.currentProfile.PhoneNumber
	}
	b := okta.CreateUserRequest{
		Credentials: &okta.UserCredentials{
			Password: &okta.PasswordCredential{
				Value: th.currentProfile.Password,
			},
		},
		Profile: &profile,
	}
	u, _, err := th.oktaClient.User.CreateUser(context.Background(), b, nil)
	if err != nil {
		return err
	}
	if condition == "with" {
		err = th.enrollSMSFactor(u.Id)
		if err != nil {
			return err
		}
	}
	th.currentProfile.UserID = u.Id
	return nil
}

func (th *TestHarness) user(state, name string) error {
	a18nProfile, err := th.createProfile(name)
	if err != nil {
		return err
	}
	th.currentProfile = a18nProfile
	if state == "new" {
		return nil
	}

	err = th.addUser("without")
	if err != nil {
		return err
	}

	p := map[string]string{
		"zoneinfo":     "America/Los_Angeles",
		"given_name":   th.currentProfile.GivenName,
		"locale":       "en_US",
		"name":         fmt.Sprintf("%s %s", th.currentProfile.GivenName, th.currentProfile.FamilyName),
		"phone_number": th.currentProfile.PhoneNumber,
		"family_name":  th.currentProfile.FamilyName,
		"email":        th.currentProfile.EmailAddress,
	}
	_, _, err = th.oktaClient.Application.AssignUserToApplication(context.TODO(), th.appID, okta.AppUser{
		Credentials: &okta.AppUserCredentials{
			UserName: th.currentProfile.EmailAddress,
		},
		Id:      th.currentProfile.UserID,
		Profile: p,
	})
	if err != nil {
		return fmt.Errorf("failed to assign user to the app: %w", err)
	}

	idxClient, err := idx.NewClient()
	if err != nil {
		return fmt.Errorf("new IdX client error: %w", err)
	}
	resp, err := idxClient.InitLogin(context.TODO())
	if err != nil {
		return err
	}
	up := &idx.IdentifyRequest{
		Identifier: th.currentProfile.EmailAddress,
		Credentials: idx.Credentials{
			Password: th.currentProfile.Password,
		},
	}
	if resp.HasStep(idx.LoginStepIdentify) {
		resp, err = resp.Identify(context.TODO(), up)
		if err != nil {
			return err
		}
	} else if resp.HasStep(idx.LoginStepSuccess) {
		return nil
	} else {
		return fmt.Errorf("failed to identify new user, expected step is %s, actual: %s", idx.LoginStepIdentify, resp.AvailableSteps())
	}

	if resp.HasStep(idx.LoginStepSetupNewPassword) {
		newPassword := randomString()
		resp, err = resp.SetNewPassword(context.TODO(), newPassword)
		if err != nil {
			return err
		}
		th.currentProfile.Password = newPassword
	} else if resp.HasStep(idx.LoginStepSuccess) {
		return nil
	}

	if resp.HasStep(idx.LoginStepEmailVerification) {
		resp, err = resp.VerifyEmail(context.TODO())
		if err != nil {
			return err
		}

	} else if resp.HasStep(idx.LoginStepSuccess) {
		return nil
	} else {
		return fmt.Errorf("failed to identify new user, expected step is %s, actual: %s", idx.LoginStepEmailVerification, resp.AvailableSteps())
	}

	if resp.HasStep(idx.LoginStepEmailConfirmation) {
		code, err := th.verificationCode(th.currentProfile.URL, EmailCodeType)
		if err != nil {
			return err
		}
		resp, err = resp.ConfirmEmail(context.TODO(), code)
		if err != nil {
			return err
		}
	} else if resp.HasStep(idx.LoginStepSuccess) {
		return nil
	} else {
		return fmt.Errorf("failed to identify new user, expected step is %s, actual: %s", idx.LoginStepEmailConfirmation, resp.AvailableSteps())
	}

	if resp.HasStep(idx.LoginStepSkip) {
		resp, err = resp.Skip(context.TODO())
		if err != nil {
			return err
		}
	}
	if !resp.HasStep(idx.LoginStepSuccess) {
		return fmt.Errorf("failed to identify new user, expected step is %s, actual: %s", idx.LoginStepSuccess, resp.AvailableSteps())
	}

	return nil
}

func (th *TestHarness) selectSMS() error {
	if err := th.clicksFormCheckItem(`input[id="sms"]`, th.waitForEnrollPhoneMethodForm); err != nil {
		return err
	}

	return th.clicksButtonWithText(`button[type="submit"]`, "Continue")
}

func (th *TestHarness) code() error {
	return th.seesElement(`input[id="code"]`)
}

func (th *TestHarness) selectsFactor(factor string) error {
	var err error
	switch factor {
	case "Email":
		err = th.clicksButton(`input[id="push_email"]`)
	case "Phone":
		err = th.clicksButton(`input[id="push_phone"]`)
	}
	if err != nil {
		return err
	}
	return th.clicksButtonWithText(`button[type="submit"]`, "Continue")
}

func (th *TestHarness) submitsTheForm(form string) error {
	switch form {
	case "Login":
		return th.submitsForm(`button[type="submit"]`, "Login")
	case "Registration":
		return th.submitsForm(`button[type="submit"]`, "Register")
	case "New Password", "Code", "Recovery", "New Phone", "Verify":
		return th.submitsForm(`button[type="submit"]`, "Submit")
	}
	return fmt.Errorf("'%s' submission form is undefined", form)
}

func (th *TestHarness) seesErrorMessage(message string) error {
	return th.matchErrorMessage(message)
}

func (th *TestHarness) loginToApplication() error {
	err := th.clickLink("Sign In")
	if err != nil {
		return err
	}
	if err = th.waitForPageRender(); err != nil {
		return err
	}
	if err = th.waitForLoginForm(); err != nil {
		return err
	}
	if err = th.fillsInUsername(); err != nil {
		return err
	}
	if err = th.fillsInPassword(); err != nil {
		return err
	}
	if err = th.submitsLoginForm(); err != nil {
		return err
	}
	if err = th.waitForPageRender(); err != nil {
		return err
	}
	text := fmt.Sprintf("Welcome, %s.", th.currentProfile.DisplayName)
	return th.seesElementWithText(`html body h1`, text)
}

func (th *TestHarness) checkEntryPoints() error {
	baseURL := fmt.Sprintf("http://%s", th.server.Address())
	links := []struct {
		text string
		href string
	}{
		{
			text: "Sign In",
			href: fmt.Sprintf("%s/login", baseURL),
		},
		{
			text: "Sign Up",
			href: fmt.Sprintf("%s/register", baseURL),
		},
		{
			text: "Password Recovery",
			href: fmt.Sprintf("%s/passwordRecovery", baseURL),
		},
		{
			text: "Logout",
			href: fmt.Sprintf("%s/logout", baseURL),
		},
	}

	for _, link := range links {
		elem, err := th.wd.FindElement(selenium.ByLinkText, link.text)
		if err != nil {
			return err
		}
		href, err := elem.GetAttribute("href")
		if !strings.HasSuffix(link.href, href) {
			return fmt.Errorf("expected to find link %q with href %q but found it with %q", link.text, link.href, href)
		}
	}

	return nil
}

func (th *TestHarness) isLoggedOut() error {
	text := fmt.Sprintf("Welcome, %s.", claimItem("name"))
	return th.doesNotSeeElementWithText(`html body h1`, text)
}

func (th *TestHarness) clicksOnButton(button string) error {
	switch button {
	case "Forgot Password":
		return th.clickLink("Forgot your password?")
	case "Logout":
		return th.clicksButtonWithText(`button[type="submit"]`, "Logout")
	case "Login with Facebook":
		return th.clicksButtonWithText(`span[class="px-4"]`, "FB IdP")
	case "Skip":
		return th.clicksInputWithValue(`input[type="submit"]`, "Skip")
	}
	return fmt.Errorf("'%s' button is undefined", button)
}

func (th *TestHarness) seesLogoutButton() error {
	return th.seesElementWithText(`button[type="submit"]`, "Logout")
}

func (th *TestHarness) profile(assertion string) error {
	switch assertion {
	case "sees":
		err := th.seesElementIDWithValue("email-value", th.currentProfile.EmailAddress)
		if err != nil {
			return err
		}
		return th.seesElementIDWithValue("name-value", th.currentProfile.DisplayName)
	case "doesn't see":
		err := th.doesntSeeElementIDWithValue("email-value", th.currentProfile.EmailAddress)
		if err != nil {
			return err
		}
		return th.doesntSeeElementIDWithValue("name-value", th.currentProfile.DisplayName)

	}
	return errors.New("invalid assertion, should be either 'sees' or 'doesn't see'")
}

func (th *TestHarness) redirected(view string) error {
	switch view {
	case "Password Recovery":
		return th.isView(fmt.Sprintf("http://%s/passwordRecovery", th.server.Address()))
	case "Root":
		return th.isView(fmt.Sprintf("http://%s/", th.server.Address()))
	}
	return errors.New("invalid view, should be either 'Password Recovery' or 'Root'")
}

func (th *TestHarness) fillsNewPassword(scenario string) error {
	switch scenario {
	case "enroll":
		if th.currentProfile == nil {
			return errors.New("test harness doesn't have a current profile")
		}
		err := th.fillsInFormValue(`input[name="newPassword"]`, th.currentProfile.Password, th.waitForEnrollPasswordForm)
		if err != nil {
			return err
		}
		return th.fillsInFormValue(`input[name="confirmPassword"]`, th.currentProfile.Password, th.waitForEnrollPasswordForm)
	case "reset":
		p := randomString()
		err := th.fillsInFormValue(`input[name="newPassword"]`, p, th.waitForResetPasswordForm)
		if err != nil {
			return err
		}
		return th.fillsInFormValue(`input[name="confirmPassword"]`, p, th.waitForResetPasswordForm)
	}
	return errors.New("invalid scenario, should be either 'enroll' or 'reset'")
}

func (th *TestHarness) fillsInNewEmailOrPhoneNumber(state, sourceType string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	switch sourceType {
	case "email":
		email := th.currentProfile.EmailAddress
		if state == "invalid" {
			email = "invalid-email-address-dot-com"
		}
		return th.fillsInFormValue(`input[name="email"]`, email, th.waitForRegistrationForm)
	case "phone number":
		number := th.currentProfile.PhoneNumber
		if state == "invalid" {
			number = "not-a-phone-number"
		}
		return th.entersText(`input[name="phoneNumber"]`, number)
	}
	return errors.New("invalid source, should be either 'email' or 'phone number")
}

func (th *TestHarness) fillsInIdentity(name string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	switch name {
	case "First Name":
		return th.fillsInFormValue(`input[name="firstName"]`, th.currentProfile.GivenName, th.waitForRegistrationForm)
	case "Last Name":
		return th.fillsInFormValue(`input[name="lastName"]`, th.currentProfile.FamilyName, th.waitForRegistrationForm)
	}
	return errors.New("invalid identity field, should be either 'First Name' or 'Last Name")
}

func (th *TestHarness) listOfFactors(factorsType string) error {
	switch factorsType {
	case "enrollment":
		return th.seesElement(`form[action="/enrollFactor"]`)
	case "verification":
		return th.seesElement(`form[action="/login/factors/proceed"]`)
	}
	return errors.New("invalid factors type, should be either 'enrollment' or 'verification'")
}

func (th *TestHarness) scansAQRCode() error {
	var source string
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByCSSSelector, `img[id="qr-code"]`)
		if err != nil {
			return false, nil
		}
		source, err = elem.GetAttribute("src")
		if err != nil {
			return false, err
		}
		return true, nil
	}, defaultTimeout(), defaultInterval())
	if err != nil {
		return err
	}
	i := strings.Index(source, ",")
	if i < 0 {
		return errors.New("invalid QR Code")
	}
	dec, err := base64.StdEncoding.DecodeString(source[i+1:])
	if err != nil {
		return err
	}
	img, err := png.Decode(bytes.NewReader(dec))
	if err != nil {
		return fmt.Errorf("image.Decode error: %w", err)
	}
	qrCodes, err := goqr.Recognize(img)
	if err != nil {
		return fmt.Errorf("Recognize failed: %v\n", err)
	}
	if len(qrCodes) == 0 {
		return errors.New("didn't recognize any QR codes")
	}
	otpauth, err := url.Parse(fmt.Sprintf("%s", qrCodes[0].Payload))
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	th.googleAuth = gotp.NewDefaultTOTP(otpauth.Query()["secret"][0])
	return th.clicksButtonWithText(`button[type="submit"]`, "Continue")
}

func (th *TestHarness) fillsInOTP(state, source string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	if state == "incorrect" {
		return th.entersText(`input[name="code"]`, "000000")
	}

	var code string

	switch source {
	case "Google Authenticator":
		if th.googleAuth == nil {
			return errors.New("test harness doesn't have a google auth created")
		}
		code = th.googleAuth.Now()
	case "WebAuthN":
		return errors.New("not implemented")
	default:
		return errors.New("invalid source, should be either 'Google Authenticator' or 'WebAuthN")
	}

	return th.entersText(`input[name="code"]`, code)
}

func (th *TestHarness) fillsInTheCode(state, source string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	if state == "incorrect" {
		return th.entersText(`input[name="code"]`, "000000")
	}

	var (
		code string
		err  error
	)

	switch source {
	case "sms":
		code, err = th.verificationCode(th.currentProfile.URL, SmsCodeType)
	case "email":
		code, err = th.verificationCode(th.currentProfile.URL, EmailCodeType)
	default:
		return errors.New("invalid source, should be either 'email' or 'sms")
	}
	if err != nil {
		return fmt.Errorf("faild to find latest '%s' verification code for user %s: %v", source, th.currentProfile.EmailAddress, err)
	}

	return th.entersText(`input[name="code"]`, code)
}

func (th *TestHarness) fillsInCredentials(state, credential, action string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}

	switch action {
	case "login":
		switch credential {
		case "password":
			password := th.currentProfile.Password
			if state == "incorrect" {
				password = "wrong_password"
			}
			return th.fillsInFormValue(`input[name="password"]`, password, th.waitForLoginForm)
		case "username":
			username := th.currentProfile.EmailAddress
			if state == "incorrect" {
				username = "wrong_email@example.com"
			}
			return th.fillsInFormValue(`input[name="identifier"]`, username, th.waitForLoginForm)
		}
		return errors.New("invalid credential, should be either 'username' or 'password'")
	case "recover":
		username := th.currentProfile.EmailAddress
		if state == "incorrect" {
			username = "wrong_email@example.com"
		}
		return th.fillsInFormValue(`input[name="identifier"]`, username, th.waitForPasswordRecoveryForm)
	}

	return errors.New("invalid action, should be either 'login' or 'recover'")
}

func (th *TestHarness) navigateToTheView(view string) error {
	var dest string
	switch view {
	case "Basic Login":
		dest = fmt.Sprintf("http://%s/login", th.server.Address())
	case "Password Recovery":
		dest = fmt.Sprintf("http://%s/passwordRecovery", th.server.Address())
	case "Root":
		dest = fmt.Sprintf("http://%s/", th.server.Address())
	case "Self Service Registration":
		dest = fmt.Sprintf("http://%s/register", th.server.Address())
	default:
		return errors.New("invalid view")
	}
	err := th.wd.Get(dest)
	if err != nil {
		return err
	}
	return th.waitForPageRender()
}
