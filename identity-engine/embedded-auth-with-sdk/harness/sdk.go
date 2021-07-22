package harness

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

func (th *TestHarness) fillInOrgInfo() {
	th.org = orgData{}
	groups, _, err := th.oktaClient.Group.ListGroups(context.Background(), &query.Params{Limit: 20})
	if err != nil {
		log.Fatalf("list groups error: %+v", err)
	}
	for _, v := range groups {
		if v.Profile.Name == "Everyone" {
			th.org.everyoneGroupID = v.Id
		}
		if v.Profile.Name == "MFA Required" {
			th.org.mfaRequiredGroupID = v.Id
		}
	}
	apps, _, err := th.oktaClient.Application.ListApplications(context.Background(), &query.Params{Q: "Golang IDX Web App"})
	if err != nil {
		log.Fatalf("list apps error: %+v", err)
	}
	if len(apps) != 1 {
		log.Fatal("more than one app with name 'Golang IDX Web App' exists")
	}
	req, err := th.oktaClient.GetRequestExecutor().NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies?type=Okta:SignOn&resourceId=%s", apps[0].(*okta.Application).Id), nil)
	if err != nil {
		log.Fatalf("new request error: %+v", err)
	}
	var policies []okta.Policy
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &policies)
	if err != nil {
		log.Fatalf("do request error: %+v", err)
	}
	for _, v := range policies {
		if v.Name == "Golang IDX Web App" {
			th.org.policyID = v.Id
			break
		}
	}
	req, err = th.oktaClient.GetRequestExecutor().NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules", th.org.policyID), nil)
	if err != nil {
		log.Fatalf("new request error: %+v", err)
	}
	var rules []OktaAppSignOnPolicyRule
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &rules)
	if err != nil {
		log.Fatalf("do request error: %+v", err)
	}
	for _, v := range rules {
		if v.Name != "MFA Rule" {
			continue
		}
		th.org.mfaRuleID = v.ID
		break
	}
}

type OktaAppSignOnPolicyRule struct {
	Name        string                `json:"name"`
	ID          string                `json:"id"`
	Type        string                `json:"type"`
	Priority    int                   `json:"priority"`
	Conditions  []PolicyRuleCondition `json:"conditions"`
	Action      string                `json:"action"`
	Requirement struct {
		VerificationMethod struct {
			FactorMode       string `json:"factorMode"`
			Type             string `json:"type"`
			ReauthenticateIn string `json:"reauthenticateIn"`
			Constraints      []struct {
				Knowledge struct {
					Types            []string `json:"types"`
					ReauthenticateIn string   `json:"reauthenticateIn"`
				} `json:"knowledge"`
			} `json:"constraints"`
		} `json:"verificationMethod"`
		OktaSignOnSettings interface{} `json:"oktaSignOnSettings"`
	} `json:"requirement"`
	Status              string `json:"status"`
	ResourceDisplayName struct {
		Value     string `json:"value"`
		Sensitive bool   `json:"sensitive"`
	} `json:"resourceDisplayName"`
	ResourceID          string      `json:"resourceId"`
	ResourceAlternateID interface{} `json:"resourceAlternateId"`
	ResourceType        string      `json:"resourceType"`
	Default             bool        `json:"default"`
}

type PolicyRuleCondition struct {
	Key   string   `json:"key"`
	Op    string   `json:"op"`
	Value []string `json:"value"`
}

func (th *TestHarness) deleteProfileFromOrg(userID string) error {
	users, _, err := th.oktaClient.User.ListUsers(context.Background(), &query.Params{
		Q:     "Mary",
		Limit: 100,
	})
	if err != nil {
		return err
	}
	for _, u := range users {
		e := *u.Profile
		if !strings.HasSuffix(e["email"].(string), "a18n.help") {
			continue
		}
		// deactivate
		resp, err := th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), u.Id, nil)
		// suppress Not Found error
		if err != nil && resp != nil && resp.StatusCode != http.StatusNotFound {
			return err
		}
		// delete
		_, err = th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), u.Id, nil)
		// suppress Not Found error
		if err != nil && resp != nil && resp.StatusCode != http.StatusNotFound {
			return err
		}
	}
	if userID == "" {
		return nil
	}
	// deactivate
	resp, err := th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), userID, nil)
	// suppress Not Found error
	if err != nil && resp != nil && resp.StatusCode != http.StatusNotFound {
		return err
	}
	time.Sleep(time.Second) // it's silly to put sleeps in the code, but it does not affect the tests themselves
	// delete
	_, err = th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), userID, nil)
	// suppress Not Found error
	if err != nil && resp != nil && resp.StatusCode != http.StatusNotFound {
		return err
	}
	return nil
}

func (th *TestHarness) resetAppSignOnPolicyRule() error {
	req, err := th.oktaClient.GetRequestExecutor().NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.policyID, th.org.mfaRuleID), nil)
	if err != nil {
		return err
	}
	var rule OktaAppSignOnPolicyRule
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &rule)
	if err != nil {
		return err
	}
	for i := range rule.Conditions {
		if rule.Conditions[i].Key == "Okta:Group" {
			// no need to update
			if len(rule.Conditions[i].Value) == 1 && rule.Conditions[i].Value[0] == th.org.mfaRequiredGroupID {
				return nil
			}
			rule.Conditions[i].Value = []string{th.org.mfaRequiredGroupID}
			break
		}
	}
	req, err = th.oktaClient.GetRequestExecutor().NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.policyID, th.org.mfaRuleID), &rule)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, nil)
	if err != nil {
		return err
	}
	req, err = th.oktaClient.GetRequestExecutor().NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/policies/%s/rules/%s/lifecycle/deactivate", th.org.policyID, th.org.mfaRuleID), nil)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, nil)
	return err
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

func (th *TestHarness) enrollSMSFactor(uID string) error {
	factor := []byte(fmt.Sprintf(`{
	  "factorType": "sms",
	  "provider": "OKTA",
	  "profile": {
	    "phoneNumber": "%s"
	  }
	}`, th.currentProfile.PhoneNumber))
	req, err := th.oktaClient.GetRequestExecutor().
		WithAccept("application/json").
		WithContentType("application/json").
		NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/users/%v/factors", uID), factor)
	if err != nil {
		return err
	}
	var uf userFactor
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &uf)
	if err != nil {
		return err
	}
	code, err := th.verificationCode(th.currentProfile.URL, SMS_CODE_TYPE)
	if err != nil {
		return fmt.Errorf("faild to find latest verification code for user %s: %v", th.currentProfile.EmailAddress, err)
	}
	_, _, err = th.oktaClient.UserFactor.ActivateFactor(context.Background(), uID, uf.ID, okta.ActivateFactorRequest{PassCode: code}, nil)
	return err
}

func (th *TestHarness) addUserToGroup(groupName string) error {
	if th.currentProfile == nil {
		return errors.New("test harness doesn't have a current profile")
	}
	// user is auto assigned to this group
	if groupName == "Everyone" {
		return nil
	}
	groups, _, err := th.oktaClient.Group.ListGroups(context.Background(), &query.Params{Q: groupName})
	if err != nil {
		return err
	}
	for _, g := range groups {
		if g.Profile.Name != groupName {
			continue
		}
		_, err = th.oktaClient.Group.AddUserToGroup(context.Background(), g.Id, th.currentProfile.UserID)
		return err
	}
	return fmt.Errorf("group %s doesn't exist in the org", groupName)
}

func (th *TestHarness) singOnPolicyRuleGroup() error {
	req, err := th.oktaClient.GetRequestExecutor().NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.policyID, th.org.mfaRuleID), nil)
	if err != nil {
		return err
	}
	var rule OktaAppSignOnPolicyRule
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &rule)
	if err != nil {
		return err
	}
	for i := range rule.Conditions {
		if rule.Conditions[i].Key == "Okta:Group" {
			rule.Conditions[i].Value = []string{th.org.everyoneGroupID}
			break
		}
	}
	req, err = th.oktaClient.GetRequestExecutor().NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.policyID, th.org.mfaRuleID), &rule)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, nil)
	if err != nil {
		return err
	}
	req, err = th.oktaClient.GetRequestExecutor().NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/policies/%s/rules/%s/lifecycle/activate", th.org.policyID, th.org.mfaRuleID), nil)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, nil)
	return err
}
