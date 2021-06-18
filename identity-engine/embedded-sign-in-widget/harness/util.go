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

func (th *TestHarness) navigateToTheRootView() error {
	rootURL := fmt.Sprintf("http://%s/", th.server.Address())
	err := th.wd.Get(rootURL)
	if err != nil {
		return err
	}

	return th.waitForPageRender()
}

func (th *TestHarness) isRootView() error {
	if err := th.waitForPageRender(); err != nil {
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
	return th.fillsInFormValue(`input[name="credentials.passcode"]`, th.currentProfile.Password, th.waitForLoginForm)
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
	err := th.submitsForm(`input[type="submit"]`, "Next")
	if err != nil {
		return err
	}
	// FIXME the login is done with ajax, find a more elegant way to wait other than sleeping
	time.Sleep(5 * time.Second)
	return th.waitForPageRender()
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
