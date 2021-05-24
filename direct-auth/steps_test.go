package main

import (
	"github.com/cucumber/godog"
)

func herAccessTokenIsRevoked() error {
	return godog.ErrPending
}

func herAppSessionIsDestroyed() error {
	return godog.ErrPending
}

func maryClicksTheLogoutButton() error {
	return godog.ErrPending
}

func maryNavigatesToTheRootView() error {
	return godog.ErrPending
}

func maryNavigatesToTheRootViewWITHAnAuthentcationSession() error {
	return godog.ErrPending
}

func marySeesALogoutButton() error {
	return godog.ErrPending
}

func marySeesATableWithTheClaimsFromTheUserinfoResponse() error {
	return godog.ErrPending
}

func sheIsRedirectedBackToTheRootView() error {
	return godog.ErrPending
}

func theRootPageShowsLinksToTheEntryPointsAsDefinedInHttpsoktawikiatlassiannetlcPwDVmT(arg1, arg2 int) error {
	return godog.ErrPending
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	ctx.Step(`^her access token is revoked$`, herAccessTokenIsRevoked)
	ctx.Step(`^her app session is destroyed$`, herAppSessionIsDestroyed)
	ctx.Step(`^Mary clicks the logout button$`, maryClicksTheLogoutButton)
	ctx.Step(`^Mary navigates to the Root View$`, maryNavigatesToTheRootView)
	ctx.Step(`^Mary navigates to the Root View WITH an authentcation session$`, maryNavigatesToTheRootViewWITHAnAuthentcationSession)
	ctx.Step(`^Mary sees a logout button$`, marySeesALogoutButton)
	ctx.Step(`^Mary sees a table with the claims from the \/userinfo response$`, marySeesATableWithTheClaimsFromTheUserinfoResponse)
	ctx.Step(`^she is redirected back to the Root View$`, sheIsRedirectedBackToTheRootView)
	ctx.Step(`^the Root Page shows links to the Entry Points as defined in https:\/\/oktawiki\.atlassian\.net\/l\/c\/Pw(\d+)DVm(\d+)t$`, theRootPageShowsLinksToTheEntryPointsAsDefinedInHttpsoktawikiatlassiannetlcPwDVmT)
}
