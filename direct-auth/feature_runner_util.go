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
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tebeka/selenium"
)

func debug(text string) {
	if os.Getenv("DEBUG") == "true" {
		fmt.Println(text)
	}
}

func defaultTimeout() time.Duration {
	return time.Duration(time.Second * 10)
}

func defaultInterval() time.Duration {
	return time.Duration(time.Second * 3)
}

func claims() map[string]string {
	claimsJSON := os.Getenv("CLAIMS")
	claims := map[string]string{}
	err := json.Unmarshal([]byte(claimsJSON), &claims)
	if err != nil {
		fmt.Printf("unable to unmarshal env var CLAIMS %q\n", claimsJSON)
		return map[string]string{}
	}
	return claims
}

func claimItem(key string) string {
	value, _ := claims()[key]
	return value
}

func (th *TestHarness) navigateToTheRootView() error {
	debug("navigateToTheRootView")
	rootURL := fmt.Sprintf("http://%s/", th.server.Address())
	err := th.wd.Get(rootURL)
	if err != nil {
		return err
	}

	return th.waitForPageRender()
}

func (th *TestHarness) isRootView() error {
	debug("isRootView")
	rootURL := fmt.Sprintf("http://%s/", th.server.Address())

	url, err := th.wd.CurrentURL()
	if err != nil {
		return err
	}

	if rootURL != url {
		return fmt.Errorf("isRootView expects %q url, finds %q url", rootURL, url)

	}

	return nil
}

func (th *TestHarness) waitForPageRender() error {
	debug("waitForPageRender")
	return th.seesElement(`html body h1`)
}

func (th *TestHarness) checkEntryPoints() error {
	debug("cehckEntryPoints")
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
			href: fmt.Sprintf("%s/basic-login", baseURL),
		},
		{
			text: "Logout",
			href: fmt.Sprintf("%s/basic-login", baseURL),
		},
	}

	for _, link := range links {
		elem, err := th.wd.FindElement(selenium.ByLinkText, link.text)
		if err != nil {
			return err
		}
		href, err := elem.GetAttribute("href")
		if href != link.href {
			return fmt.Errorf("expected to find link %q with href %q but found it with %q", link.text, link.href, href)
		}
	}

	return nil
}

func (th *TestHarness) waitForLoginForm() error {
	debug("waitForLoginForm")
	return th.seesElement(`form[action="/login"]`)
}

func (th *TestHarness) loginToApplication() error {
	debug("loginToApplication")
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

	if err = th.entersText(`input[name="identifier"]`, os.Getenv("EMAIL")); err != nil {
		return err
	}

	if err = th.entersText(`input[name="password"]`, os.Getenv("PASSWORD")); err != nil {
		return err
	}

	if err = th.clicksButtonWithText(`button[type="submit"]`, "Login"); err != nil {
		return err
	}

	if err = th.waitForPageRender(); err != nil {
		return err
	}

	text := fmt.Sprintf("Welcome, %s.", claimItem("name"))
	return th.seesElementWithText(`html body h1`, text)
}

func (th *TestHarness) isLoggedOut() error {
	debug("isLoggedOut")

	text := fmt.Sprintf("Welcome, %s.", claimItem("name"))
	return th.doesNotSeeElementWithText(`html body h1`, text)
}

func (th *TestHarness) seesClaimsTable() error {
	debug("seesClaimsTable")

	claims := claims()

	for claim, value := range claims {
		keyID := fmt.Sprintf("%s-key", claim)
		err := th.seesElementIDWithValue(keyID, claim)
		if err != nil {
			return err
		}

		valID := fmt.Sprintf("%s-value", claim)
		if err = th.seesElementIDWithValue(valID, value); err != nil {
			return err
		}
	}

	return nil
}

func (th *TestHarness) seesLogoutButton() error {
	return th.seesElementWithText(`button[type="submit"]`, "Logout")
}

func (th *TestHarness) clicksLogoutButton() error {
	result := th.clicksButtonWithText(`button[type="submit"]`, "Logout")
	return result
}

func (th *TestHarness) seesElement(selector string) error {
	debug(fmt.Sprintf("seesElement %q\n", selector))
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		if _, err := th.wd.FindElement(selenium.ByCSSSelector, selector); err != nil {
			return false, nil
		}

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) clickLink(text string) error {
	debug(fmt.Sprintf("clickLink %q\n", text))
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
	debug(fmt.Sprintf("entersText %q %q\n", selector, text))
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {

		// Sleep is a hack to get OSX/Selenium synched up for text input.
		time.Sleep(500 * time.Millisecond)

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

func (th *TestHarness) seesElementWithText(selector, text string) error {
	debug(fmt.Sprintf("seesElementWithText %q %q\n", selector, text))
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

		return true, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) doesNotSeeElementWithText(selector, text string) error {
	debug(fmt.Sprintf("doesNotSeeElementWithText %q %q\n", selector, text))
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elem, err := th.wd.FindElement(selenium.ByCSSSelector, selector)
		if err != nil {
			return true, nil
		}

		elemText, err := elem.Text()
		if err != nil {
			return true, nil
		}
		if strings.TrimSpace(elemText) != text {
			return true, nil
		}

		return false, nil
	}, defaultTimeout(), defaultInterval())

	return err
}

func (th *TestHarness) clicksButtonWithText(selector, text string) error {
	debug(fmt.Sprintf("clicksButtonWithText %q %q\n", selector, text))
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {

		// Sleep is a hack to get OSX/Selenium synched up for text input.
		time.Sleep(500 * time.Millisecond)

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

func (th *TestHarness) seesElementIDWithValue(elementID, text string) error {
	debug(fmt.Sprintf("seesElementIDWithValue %q %q\n", elementID, text))
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
