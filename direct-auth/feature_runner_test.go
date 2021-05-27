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
	"testing"

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
	rootURL := fmt.Sprintf("http://%s/", th.server.Address())
	err := th.wd.Get(rootURL)
	return err
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
			href: fmt.Sprintf("%s/sign-up", baseURL),
		},
		{
			text: "Password Recovery",
			href: fmt.Sprintf("%s/password-recovery", baseURL),
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
		if href != link.href {
			return fmt.Errorf("expected to find link %q with href %q but found it with %q", link.text, link.href, href)
		}
	}

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
		// force a logout and go back to home
		logoutURL := fmt.Sprintf("%s%s", th.server.Address(), "logout")
		logoutXHR := fmt.Sprintf("var xhr = new XMLHttpRequest();\nxhr.open(\"POST\", %q, false);\nxhr.send('');", logoutURL)
		_, _ = th.wd.ExecuteScript(logoutXHR, nil)
		err = th.wd.Quit()
		if err != nil {
			log.Panic(err)
		}
	})

	ctx.Step(`^Mary navigates to the Root View$`, th.navigateToTheRootView)
	ctx.Step(`Root Page shows links to the Entry Points`, th.checkEntryPoints)
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
