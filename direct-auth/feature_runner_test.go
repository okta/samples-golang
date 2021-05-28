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
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
	"github.com/cucumber/messages-go/v10"
	"github.com/okta/samples-golang/direct-auth/config"
	"github.com/okta/samples-golang/direct-auth/server"
	"github.com/tebeka/selenium"
)

type TestHarness struct {
	server       *server.Server
	wd           selenium.WebDriver
	capabilities selenium.Capabilities
}

func defaultTimeout() time.Duration {
	return time.Duration(time.Second * 10)
}

func defaultInterval() time.Duration {
	return time.Duration(time.Second * 3)
}

func debug(text string) {
	if os.Getenv("DEBUG") == "true" {
		fmt.Println(text)
	}
}

func (th *TestHarness) InitializeTestSuite(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		cfg := &config.Config{
			Testing: true,
		}
		err := config.ReadConfig(cfg)
		if err != nil {
			fmt.Printf("%+v\n", err)
			os.Exit(1)
		}

		server := server.NewServer(cfg)
		th.server = server
		server.Run()
	})

	ctx.AfterSuite(func() {
		if th.server != nil {
			th.server.Stop()
		}
	})
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
	return th.clicksButtonWithText(`button[type="submit"]`, "Logout")
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
		elem, err := th.wd.FindElement(selenium.ByCSSSelector, selector)
		if err != nil {
			return false, nil
		}

		if err = elem.Clear(); err != nil {
			return false, err
		}

		if err = elem.Click(); err != nil {
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

func (th *TestHarness) clicksButtonWithText(selector, text string) error {
	debug(fmt.Sprintf("clicksButtonWithText %q %q\n", selector, text))
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
	th.capabilities = capabilities

	ctx.BeforeScenario(func(sc *messages.Pickle) {
		var err error
		th.wd, err = selenium.NewRemote(th.capabilities, os.Getenv("SELENIUM_URL"))
		if err != nil {
			log.Panic(err)
		}
	})

	ctx.AfterScenario(func(sc *messages.Pickle, err error) {
		// force a logout
		logoutXHR := fmt.Sprintf("var xhr = new XMLHttpRequest(); xhr.open(\"POST\", \"/logout\", false); xhr.send(\"\");")
		_, _ = th.wd.ExecuteScript(logoutXHR, nil)
		err = th.wd.Quit()
		if err != nil {
			log.Panic(err)
		}
	})

	ctx.Step(`navigates to the Root View`, th.navigateToTheRootView)
	ctx.Step(`Root Page shows links to the Entry Points`, th.checkEntryPoints)
	ctx.Step(`logs in to the Application`, th.loginToApplication)
	ctx.Step(`sees a table with the claims`, th.seesClaimsTable)
	ctx.Step(`sees a logout button`, th.seesLogoutButton)
	ctx.Step(`clicks the logout button`, th.clicksLogoutButton)
	ctx.Step(`access token is revoked`, th.noop)  // FIXME
	ctx.Step(`app session is destroyed`, th.noop) // FIXME
	ctx.Step(`is redirected back to the Root View`, th.isRootView)
}

var opts = godog.Options{
	Output: colors.Colored(os.Stdout),
	Format: "pretty", // "cucumber", "events", "junit", "pretty", "progress"
	Strict: true,
	Paths:  []string{"features"},
	//ShowStepDefinitions: true,
}

func TestMain(m *testing.M) {
	th := &TestHarness{}
	status := godog.TestSuite{
		Name:                 "00_root_page_test",
		TestSuiteInitializer: th.InitializeTestSuite,
		ScenarioInitializer:  th.InitializeScenario,
		Options:              &opts,
	}.Run()

	os.Exit(status)
}
