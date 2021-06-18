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
	"os"
	"testing"

	"github.com/cucumber/godog"
	flag "github.com/spf13/pflag"

	"github.com/okta/samples-golang/identity-engine/embedded-sign-in-widget/harness"
)

var godogOptions = godog.Options{
	Format: "pretty", // "cucumber", "events", "junit", "pretty", "progress"
}

func init() {
	// facilitates godog flags into test e.g.
	// go test -v --godog.format=pretty --godog.tags=wip
	godog.BindCommandLineFlags("godog.", &godogOptions)
}

func TestMain(m *testing.M) {
	flag.Parse()
	godogOptions.Paths = flag.Args()

	th := harness.NewTestHarness()

	status := godog.TestSuite{
		Name:                 "Golang Embedded Widget sample feature tests",
		TestSuiteInitializer: th.InitializeTestSuite,
		ScenarioInitializer:  th.InitializeScenario,
		Options:              &godogOptions,
	}.Run()

	// Optional: Run `testing` package's logic besides godog.
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}
