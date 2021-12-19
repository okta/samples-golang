package harness

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
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
	accessPolicy := linksValue(apps[0].(*okta.Application).Links, "accessPolicy", "href")
	if accessPolicy == "" {
		log.Fatalf("app does not support sign-on policy or this feature is not available")
	}
	th.org.signOnPolicy = path.Base(accessPolicy)
	rules, _, err := th.oktaClient.Policy.ListPolicyRules(context.Background(), path.Base(accessPolicy))
	if err != nil {
		log.Fatalf("failed to gat app sign on policy rules: %+v", err)
	}
	for _, v := range rules {
		if v.Name != "MFA Rule" {
			continue
		}
		th.org.signOnPolicyRule = v.Id
		break
	}
}

func linksValue(links interface{}, keys ...string) string {
	if links == nil {
		return ""
	}
	sl, ok := links.([]interface{})
	if ok {
		links = sl[0]
	}
	if len(keys) == 0 {
		v, ok := links.(string)
		if !ok {
			return ""
		}
		return v
	}
	l, ok := links.(map[string]interface{})
	if !ok {
		return ""
	}
	if len(keys) == 1 {
		return linksValue(l[keys[0]])
	}
	return linksValue(l[keys[0]], keys[1:]...)
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

type UserFactorsEnrolled struct {
	Id     string `json:"id"`
	Type   string `json:"type"`
	Key    string `json:"key"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func (th *TestHarness) deleteProfileFromOrg() error {
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
	if th.currentProfile == nil || th.currentProfile.UserID == "" || th.currentProfile.KeepProfile {
		return nil
	}
	// deactivate
	resp, err := th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), th.currentProfile.UserID, nil)
	// suppress Not Found error
	if err != nil && resp != nil && resp.StatusCode != http.StatusNotFound {
		return err
	}
	time.Sleep(time.Second) // it's silly to put sleeps in the code, but it does not affect the tests themselves
	// delete
	_, err = th.oktaClient.User.DeactivateOrDeleteUser(context.Background(), th.currentProfile.UserID, nil)
	// suppress Not Found error
	if err != nil && resp != nil && resp.StatusCode != http.StatusNotFound {
		return err
	}
	return nil
}

func (th *TestHarness) resetAppSignOnPolicyRule() error {
	re := th.oktaClient.CloneRequestExecutor()
	req, err := re.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.signOnPolicy, th.org.signOnPolicyRule), nil)
	if err != nil {
		return err
	}
	var rule okta.AccessPolicyRule
	_, err = re.Do(context.Background(), req, &rule)
	if err != nil {
		return err
	}
	rule.Conditions.People.Groups.Include = []string{th.org.mfaRequiredGroupID}
	req, err = re.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.signOnPolicy, th.org.signOnPolicyRule), &rule)
	if err != nil {
		return err
	}
	_, err = re.Do(context.Background(), req, nil)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.Policy.DeactivatePolicyRule(context.Background(), th.org.signOnPolicy, th.org.signOnPolicyRule)
	if err != nil {
		return fmt.Errorf("failed to deactivate policy rule: %w", err)
	}
	return nil
}

func (th *TestHarness) disableMFAEnrollRules() error {
	return nil
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
	re := th.oktaClient.CloneRequestExecutor()
	req, err := re.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.signOnPolicy, th.org.signOnPolicyRule), nil)
	if err != nil {
		return err
	}
	var rule okta.AccessPolicyRule
	_, err = re.Do(context.Background(), req, &rule)
	if err != nil {
		return err
	}
	rule.Conditions.Groups.Include = []string{th.org.everyoneGroupID}
	req, err = re.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.signOnPolicy, th.org.signOnPolicyRule), &rule)
	if err != nil {
		return err
	}
	_, err = re.Do(context.Background(), req, nil)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.Policy.ActivatePolicyRule(context.Background(), th.org.signOnPolicy, th.org.signOnPolicyRule)
	if err != nil {
		return fmt.Errorf("failed to activate policy rule: %w", err)
	}
	return nil
}
