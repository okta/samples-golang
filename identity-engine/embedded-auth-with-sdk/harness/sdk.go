package harness

import (
	"context"
	"errors"
	"fmt"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"net/http"
)

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

func (th *TestHarness) ListAppSignOnPolicyRules(ctx context.Context, policyID string) ([]okta.AccessPolicyRule, *okta.Response, error) {
	re := th.oktaClient.CloneRequestExecutor()
	url := fmt.Sprintf("/api/v1/policies/%v/rules", policyID)
	req, err := re.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	var appSignOnPolicyRules []okta.AccessPolicyRule
	resp, err := re.Do(ctx, req, &appSignOnPolicyRules)
	if err != nil {
		return nil, resp, err
	}
	return appSignOnPolicyRules, resp, nil
}

func (th *TestHarness) UpdateAppSignOnPolicyRule(ctx context.Context, policyID, ruleId string, body okta.AccessPolicyRule) (*okta.AccessPolicyRule, *okta.Response, error) {
	re := th.oktaClient.CloneRequestExecutor()
	url := fmt.Sprintf("/api/v1/policies/%v/rules/%v", policyID, ruleId)
	req, err := re.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodPut, url, body)
	if err != nil {
		return nil, nil, err
	}
	var appSignOnPolicyRule *okta.AccessPolicyRule
	resp, err := re.Do(ctx, req, &appSignOnPolicyRule)
	if err != nil {
		return nil, resp, err
	}
	return appSignOnPolicyRule, resp, nil
}

func (th *TestHarness) ListPolicies(ctx context.Context, qp *query.Params) ([]Policy, *okta.Response, error) {
	re := th.oktaClient.CloneRequestExecutor()
	url := fmt.Sprintf("/api/v1/policies")
	if qp != nil {
		url = url + qp.String()
	}
	req, err := re.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	var policies []Policy
	resp, err := re.Do(ctx, req, &policies)
	if err != nil {
		return nil, resp, err
	}
	return policies, resp, nil
}

// UpdatePolicy updates a policy.
func (th *TestHarness) UpdatePolicy(ctx context.Context, policyID string, body Policy) (*Policy, *okta.Response, error) {
	re := th.oktaClient.CloneRequestExecutor()
	url := fmt.Sprintf("/api/v1/policies/%v", policyID)
	req, err := re.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodPut, url, body)
	if err != nil {
		return nil, nil, err
	}
	var policy *Policy
	resp, err := re.Do(ctx, req, &policy)
	if err != nil {
		return nil, resp, err
	}
	return policy, resp, nil
}

func (th *TestHarness) resetAppSignOnPolicyRule() error {
	re := th.oktaClient.CloneRequestExecutor()
	req, err := re.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.appSignOnPolicy, th.org.signOnPolicyRule), nil)
	if err != nil {
		return err
	}
	var rule okta.AccessPolicyRule
	_, err = re.Do(context.Background(), req, &rule)
	if err != nil {
		return err
	}
	if rule.Conditions.People.Groups != nil {
		rule.Conditions.People.Groups.Include = []string{th.org.mfaRequiredGroupID}
	} else {
		rule.Conditions.People.Groups = &okta.GroupCondition{
			Include: []string{th.org.mfaRequiredGroupID},
		}
	}

	req, err = re.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.appSignOnPolicy, th.org.signOnPolicyRule), &rule)
	if err != nil {
		return err
	}
	_, err = re.Do(context.Background(), req, nil)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.Policy.DeactivatePolicyRule(context.Background(), th.org.appSignOnPolicy, th.org.signOnPolicyRule)
	if err != nil {
		return fmt.Errorf("failed to deactivate policy rule: %w", err)
	}
	return nil
}

func (th *TestHarness) disableMFAEnrollRules() error {
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
	code, err := th.verificationCode(th.currentProfile.URL, SmsCodeType)
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
	req, err := re.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.appSignOnPolicy, th.org.signOnPolicyRule), nil)
	if err != nil {
		return err
	}
	var rule okta.AccessPolicyRule
	_, err = re.Do(context.Background(), req, &rule)
	if err != nil {
		return err
	}
	rule.Conditions.Groups.Include = []string{th.org.everyoneGroupID}
	req, err = re.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/policies/%s/rules/%s", th.org.appSignOnPolicy, th.org.signOnPolicyRule), &rule)
	if err != nil {
		return err
	}
	_, err = re.Do(context.Background(), req, nil)
	if err != nil {
		return err
	}
	_, err = th.oktaClient.Policy.ActivatePolicyRule(context.Background(), th.org.appSignOnPolicy, th.org.signOnPolicyRule)
	if err != nil {
		return fmt.Errorf("failed to activate policy rule: %w", err)
	}
	return nil
}
