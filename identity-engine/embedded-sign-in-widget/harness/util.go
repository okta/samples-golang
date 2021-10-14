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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tebeka/selenium"
)

const (
	ROOT_VIEW_H1 = "Embedded Sign-in Widget + Golang Example"
)

func defaultTimeout() time.Duration {
	return time.Duration(time.Second * 10)
}

func defaultInterval() time.Duration {
	return time.Duration(time.Second * 3)
}

func claims() map[string]string {
	claimsJSON := os.Getenv("OKTA_IDX_CLAIMS")
	claims := map[string]string{}
	err := json.Unmarshal([]byte(claimsJSON), &claims)
	if err != nil {
		fmt.Printf("unable to unmarshal env var OKTA_IDX_CLAIMS %q\n", claimsJSON)
		return map[string]string{}
	}
	return claims
}

func claimItem(key string) string {
	value, _ := claims()[key]
	return value
}

func (th *TestHarness) googleUser() error {
	th.currentProfile = &A18NProfile{
		EmailAddress: os.Getenv("OKTA_IDX_GOOGLE_USER_NAME"),
		Password:     os.Getenv("OKTA_IDX_GOOGLE_USER_PASSWORD"),
		GivenName:    "Golang",
		FamilyName:   "User",
		DisplayName:  "Golang SDK User",
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

func (th *TestHarness) clicksNextButton() error {
	return th.submitsForm(`input[type="submit"]`, "Next")
}

func (th *TestHarness) clicksVerifyButton() error {
	return th.submitsForm(`input[type="submit"]`, "Verify")
}

func (th *TestHarness) selectsPasswordFactor() error {
	return th.clicksButtonWithText(`div[data-se="okta_password"] a`, "Select")
}

func (th *TestHarness) clicksSigninWithGoogle() error {
	if err := th.clickLink("Sign in with Google"); err != nil {
		return err
	}

	return th.seesElementWithText(`div`, `Sign in with Google`)
}

func (th *TestHarness) clicksSigninWithFacebook() error {
	if err := th.clickLink("Sign in with Facebook"); err != nil {
		return err
	}

	return th.seesElementWithText(`div`, `Log Into Facebook`)
}

func (th *TestHarness) signsInWithGoogle() error {
	if err := th.fillsInFormValue(`input[name="identifier"]`, th.currentProfile.EmailAddress, th.waitForGenericForm); err != nil {
		return err
	}

	if err := th.clickSpan("Next"); err != nil {
		return nil
	}

	if err := th.fillsInFormValue(`input[name="password"]`, th.currentProfile.Password, th.waitForGenericForm); err != nil {
		return err
	}

	if err := th.clickSpan("Next"); err != nil {
		return nil
	}

	return th.seesElement(`html body h1`)
}

func (th *TestHarness) signsInWithFacebook() error {
	if err := th.fillsInFormValue(`input[name="email"]`, th.currentProfile.EmailAddress, th.waitForGenericForm); err != nil {
		return err
	}

	if err := th.fillsInFormValue(`input[name="pass"]`, th.currentProfile.Password, th.waitForGenericForm); err != nil {
		return err
	}

	if err := th.clicksButtonWithText(`button[id="loginbutton"]`, "Log In"); err != nil {
		return nil
	}

	return th.seesElement(`html body h1`)
}

func (th *TestHarness) waitForFacebookLoginForm() error {
	return th.seesElement(`form[id="login_form"]`)
}

func (th *TestHarness) clicksButtonWithText(selector, text string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByCSSSelector, selector)
		if err != nil {
			return false, nil
		}

		elemText, err := elem.Text()
		if err != nil {
			return false, nil
		}

		if strings.TrimSpace(elemText) != text {
			return false, nil
		}

		if err = elem.Click(); err != nil {
			return false, err
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) navigateToTheRootView() error {
	rootURL := fmt.Sprintf("http://%s/", th.server.Address())
	err := th.wd.Get(rootURL)
	if err != nil {
		return err
	}

	return th.waitForPageRender()
}

func (th *TestHarness) isRootView() error {
	if err := th.seesElementWithText(`h1`, ROOT_VIEW_H1); err != nil {
		return err
	}
	return th.isView("/")
}

func (th *TestHarness) isView(path string) error {
	currentURL, err := th.wd.CurrentURL()
	if err != nil {
		return err
	}
	u, _ := url.Parse(currentURL)
	if path != u.Path {
		return fmt.Errorf("isView expects path %q, finds ptath %q", path, u.Path)
	}
	return nil
}

func (th *TestHarness) waitForPageRender() error {
	return th.seesElement(`html body`)
}

func (th *TestHarness) waitForLoginForm() error {
	err := th.seesElement(`#okta-signin-widget-container`)
	if err != nil {
		return err
	}
	return th.seesElement(`form[action="/login"]`)
}

func (th *TestHarness) waitForGenericForm() error {
	return th.seesElement(`form[method="post"]`)
}

func (th *TestHarness) seesElementWithText(selector, text string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elems, err := th.wd.FindElements(selenium.ByCSSSelector, selector)
		if err != nil {
			return false, nil
		}

		for _, elem := range elems {

			elemText, err := elem.Text()
			if err != nil {
				return false, nil
			}

			if strings.TrimSpace(elemText) == text {
				return true, nil
			}
		}

		return false, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) seesClaimsTableItemAndValueFromCurrentProfile(key string) error {
	keyID := fmt.Sprintf("%s-value", key)
	var value string
	switch {
	case key == "name":
		value = th.currentProfile.DisplayName
	case key == "email":
		value = th.currentProfile.EmailAddress
	}

	return th.seesElementIDWithValue(keyID, value)
}

func (th *TestHarness) navigateToProfileView() error {
	err := th.clickLink("My Profile")
	if err != nil {
		return err
	}

	if err = th.waitForPageRender(); err != nil {
		return err
	}

	return err
}

func (th *TestHarness) navigateToLogin() error {
	err := th.navigateToTheRootView()
	if err != nil {
		return err
	}

	err = th.clickLink("Login")
	if err != nil {
		return err
	}

	return th.waitForPageRender()
}

type waitFor func() error

func (th *TestHarness) fillsInFormValue(selector, value string, waitForForm waitFor) error {
	if err := waitForForm(); err != nil {
		return err
	}

	if err := th.entersText(selector, value); err != nil {
		return err
	}

	return nil
}

func (th *TestHarness) existingUser() error {
	th.currentProfile = &A18NProfile{
		EmailAddress: os.Getenv("OKTA_IDX_USER_NAME"),
		Password:     os.Getenv("OKTA_IDX_PASSWORD"),
		DisplayName:  fmt.Sprintf("%s %s", claimItem("given_name"), claimItem("family_name")),
	}
	return nil
}

func (th *TestHarness) fillsInUsername() error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	return th.fillsInFormValue(`input[name="identifier"]`, th.currentProfile.EmailAddress, th.waitForLoginForm)
}

func (th *TestHarness) fillsInPassword() error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	err := th.fillsInFormValue(`input[name="credentials.passcode"]`, th.currentProfile.Password, th.waitForLoginForm)
	if err != nil {
		err = th.fillsInFormValue(`input[name="identifier"]`, th.currentProfile.Password, th.waitForLoginForm)
	}

	return err
}

func (th *TestHarness) seesElement(selector string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		if _, err := th.wd.FindElement(selenium.ByCSSSelector, selector); err != nil {
			return false, nil
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) clickLink(text string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByLinkText, text)
		if err != nil {
			return false, nil
		}

		if err = elem.Click(); err != nil {
			return false, err
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) clickSpan(text string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elems, err := th.wd.FindElements(selenium.ByCSSSelector, `span`)
		if err != nil {
			return false, nil
		}

		for _, elem := range elems {
			elemText, err := elem.Text()

			if strings.TrimSpace(elemText) != text {
				continue
			}

			if err = elem.Click(); err != nil {
				return false, err
			}

			return true, nil
		}

		return false, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) entersText(selector, text string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByCSSSelector, selector)
		if err != nil {
			return false, nil
		}

		if err = elem.Clear(); err != nil {
			return false, err
		}

		if err = elem.SendKeys(text); err != nil {
			return false, err
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) clicksInputWithValue(selector, value string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByCSSSelector, selector)
		if err != nil {
			return false, nil
		}

		elemValue, err := elem.GetAttribute("value")
		if err != nil {
			return false, nil
		}

		if strings.TrimSpace(elemValue) != value {
			return false, nil
		}

		if err = elem.Click(); err != nil {
			return false, err
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) seesElementIDWithValue(elementID, text string) error {
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByID, elementID)
		if err != nil {
			return false, nil
		}

		elemText, err := elem.Text()
		if err != nil {
			return false, nil
		}

		if strings.TrimSpace(elemText) != text {
			return false, nil
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) noop() error {
	return nil
}

func (th *TestHarness) submitsForm(selector, text string) error {
	return th.clicksInputWithValue(selector, text)
}

func (th *TestHarness) submitsLoginForm() error {
	err := th.submitsForm(`input[type="submit"]`, "Sign in")
	if err != nil {
		err = th.submitsForm(`input[type="submit"]`, "Next")
		if err != nil {
			return err
		}
	}

	return th.seesElementWithText(`h1`, ROOT_VIEW_H1)
}

func (th *TestHarness) destroyCurrentProfile() error {
	if th.currentProfile == nil {
		return nil
	}
	err := th.deleteProfileFromOrg(th.currentProfile.UserID)
	if err != nil {
		return err
	}
	err = th.deleteProfile(th.currentProfile)
	th.currentProfile = nil
	return err
}

func (th *TestHarness) debugSleep(amount string) error {
	// And sleep 60s
	d, err := time.ParseDuration(amount)
	if err != nil {
		return err
	}
	time.Sleep(d)
	return nil
}

func (th *TestHarness) deleteProfile(profile *A18NProfile) error {
	if profile.URL == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete, profile.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", os.Getenv("A18N_API_KEY"))
	resp, err := th.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
