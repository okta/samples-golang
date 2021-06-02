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
		// always force a logout
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
	ctx.Step(`is logged out`, th.isLoggedOut)
	ctx.Step(`is redirected back to the Root View`, th.isRootView)
}

func TestMain(m *testing.M) {
	opts := godog.Options{
		Format: "pretty", // "cucumber", "events", "junit", "pretty", "progress"
	}

	th := &TestHarness{}
	status := godog.TestSuite{
		Name:                 "Golang Direct Auth sample feature tests",
		TestSuiteInitializer: th.InitializeTestSuite,
		ScenarioInitializer:  th.InitializeScenario,
		Options:              &opts,
	}.Run()

	// TODO / FIXME (at least on OSX) godog is exiting 1 before here for some
	// reason. The os.Exit below is not executing.
	os.Exit(status)
}
