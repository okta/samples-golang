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
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"regexp"
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

	if err = th.entersText(`input[name="identifier"]`, os.Getenv("OKTA_IDX_USER_NAME")); err != nil {
		return err
	}

	if err = th.entersText(`input[name="password"]`, os.Getenv("OKTA_IDX_PASSWORD")); err != nil {
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

func (th *TestHarness) doesntSeeClaimsTable() error {
	debug("doesntSeeClaimsTable")

	claims := claims()

	for claim, value := range claims {
		keyID := fmt.Sprintf("%s-key", claim)
		err := th.doesntSeeElementIDWithValue(keyID, claim)
		if err != nil {
			return err
		}

		valID := fmt.Sprintf("%s-value", claim)
		if err = th.doesntSeeElementIDWithValue(valID, value); err != nil {
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

func (th *TestHarness) doesntSeeElementIDWithValue(elementID, text string) error {
	debug(fmt.Sprintf("doesntSeeElementIDWithValue %q %q\n", elementID, text))
	err := th.wd.WaitWithTimeoutAndInterval(func(wd selenium.WebDriver) (bool, error) {
		elems, err := th.wd.FindElements(selenium.ByID, text)
		if err != nil {
			return false, nil
		}
		if len(elems) != 0 {
			return false, fmt.Errorf("didn't expect to find element id %q with text %q in page but found %d elems", elementID, text, len(elems))
		}

		return true, nil
	}, time.Duration(time.Millisecond*50), defaultInterval())

	if err == nil {
		return nil
	}

	if matched, _ := regexp.MatchString("timeout", err.Error()); matched {
		return nil
	}

	return err
}

func (th *TestHarness) noop() error {
	return nil
}

func (th *TestHarness) navigatesToThePasswordRecoveryView() error {
	debug("navigatesToThePasswordRecoveryView")
	rootURL := fmt.Sprintf("http://%s/passwordRecovery", th.server.Address())
	err := th.wd.Get(rootURL)
	if err != nil {
		return err
	}
	return th.waitForPageRender()
}

func (th *TestHarness) inputsCorrectEmail() error {
	debug("inputsCorrectEmail")
	err := th.entersText(`input[name="identifier"]`, os.Getenv("OKTA_IDX_USER_NAME_RESET"))
	if err != nil {
		return err
	}
	return nil
}

func (th *TestHarness) submitsTheRecoveryForm() error {
	debug("submitsTheRecoveryForm")
	if err := th.clicksButtonWithText(`button[type="submit"]`, "Submit"); err != nil {
		return err
	}
	return th.waitForPageRender()
}

func (th *TestHarness) seesPageToInputTheCode() error {
	debug("seesPageToInputTheCode")
	return th.seesElement(`form[action="/passwordRecovery/code"]`)
}

func (th *TestHarness) fillsInTheCorrectCode() error {
	debug("fillsInTheCorrectCode")
	code, err := verificationCode()
	if err != nil {
		return fmt.Errorf("faild to find latest verification code for user %s: %v", os.Getenv("OKTA_IDX_USER_NAME_RESET"), err)
	}
	if err = th.entersText(`input[name="code"]`, code); err != nil {
		return err
	}
	return nil
}

func (th *TestHarness) submitsTheCodeForm() error {
	debug("submitsTheCodeForm")
	if err := th.clicksButtonWithText(`button[type="submit"]`, "Submit"); err != nil {
		return err
	}
	return nil
}

func (th *TestHarness) seesPageToSetNewPassword() error {
	return th.seesElement(`form[action="/passwordRecovery/newPassword"]`)
}

func (th *TestHarness) fillsPassword() error {
	debug("fillsPassword")
	p := randomString()
	if err := th.entersText(`input[name="newPassword"]`, p); err != nil {
		return err
	}
	if err := th.entersText(`input[name="confirmPassword"]`, p); err != nil {
		return err
	}
	return nil
}

func (th *TestHarness) submitsNewPassword() error {
	debug("submitsNewPassword")
	if err := th.clicksButtonWithText(`button[type="submit"]`, "Submit"); err != nil {
		return err
	}
	return nil
}

func (th *TestHarness) inputsIncorrectEmail() error {
	debug("inputsCorrectEmail")
	randomString()
	err := th.entersText(`input[name="identifier"]`, strings.ReplaceAll(os.Getenv("OKTA_IDX_USER_NAME_RESET"), "@", "+1@"))
	if err != nil {
		return err
	}
	return nil
}

func (th *TestHarness) noAccountError(errorAcc string) error {
	debug("noAccountError")
	errorAcc += " " + strings.ReplaceAll(os.Getenv("OKTA_IDX_USER_NAME_RESET"), "@", "+1@") + "."
	err := th.seesElementWithText(`div[class="mx-auto py-4 px-2 my-2 w-full border-2 border-red-400 bg-red-100"]`, errorAcc)
	if err != nil {
		return err
	}
	return nil
}

func verificationCode() (string, error) {
	c := &http.Client{Timeout: time.Second * 60}
	url := os.Getenv("A18N_API_URL")
	if url == "" {
		url = "https://api.a18n.help"
	}
	profileURL, err := profileURL(c, url)
	if err != nil {
		return "", err
	}
	checker := time.Tick(time.Second * 5)
	timeout := time.After(time.Minute)
loop:
	for {
		select {
		case <-timeout:
			return "", fmt.Errorf("%s didn't receive email verification code (one minute timeout)", profileURL)
		case <-checker:
			code, err := latestVerificationCode(c, profileURL)
			if err != nil {
				break loop
			}
			if code != "" {
				return code, nil
			}
		}
	}
	return "", fmt.Errorf("%s didn't receive email verification code", profileURL)
}

func latestVerificationCode(c *http.Client, profileURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/email/latest", profileURL), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", os.Getenv("A18N_API_KEY"))
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var latestEmail struct {
		MessageID   string    `json:"messageId"`
		ProfileID   string    `json:"profileId"`
		ToAddress   string    `json:"toAddress"`
		FromAddress string    `json:"fromAddress"`
		CreatedAt   time.Time `json:"createdAt"`
		Subject     string    `json:"subject"`
		URL         string    `json:"url"`
		Content     string    `json:"content"`
	}
	err = json.Unmarshal(body, &latestEmail)
	if err != nil {
		return "", err
	}
	if time.Now().UTC().Sub(latestEmail.CreatedAt.UTC()) < time.Second*30 {
		code := codeRegexp.FindString(latestEmail.Content)
		if code != "" {
			return strings.TrimSpace(code), nil
		}
	}
	return "", nil
}

var codeRegexp = regexp.MustCompile(`[:\s][0-9]{6}`)

func profileURL(c *http.Client, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/profile", url), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", os.Getenv("A18N_API_KEY"))
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var profiles struct {
		Profiles []struct {
			ProfileID    string `json:"profileId"`
			PhoneNumber  string `json:"phoneNumber"`
			EmailAddress string `json:"emailAddress"`
			DisplayName  string `json:"displayName,omitempty"`
			URL          string `json:"url"`
		} `json:"profiles"`
		Count int `json:"count"`
	}
	err = json.Unmarshal(body, &profiles)
	if err != nil {
		return "", err
	}
	userName := os.Getenv("OKTA_IDX_USER_NAME_RESET")
	for _, v := range profiles.Profiles {
		if v.EmailAddress == userName {
			return v.URL, nil
		}
	}
	return "", fmt.Errorf("profile with %s doesn't exist if REST API for receiving MFA verification codes", userName)
}

func randomString() string {
	digits := "0123456789"
	specials := "~=+%^*/()[]{}/!@#$?|"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	length := 12
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = specials[rand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	return string(buf)
}
