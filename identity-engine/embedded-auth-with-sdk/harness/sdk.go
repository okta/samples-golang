package harness

import (
	"context"
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

func (th *TestHarness) GetAppSignOnPolicyRule(ctx context.Context, policyID, ruleID string) (*okta.AccessPolicyRule, *okta.Response, error) {
	re := th.oktaClient.CloneRequestExecutor()
	url := fmt.Sprintf("/api/v1/policies/%v/rules/%s", policyID, ruleID)
	req, err := re.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	var appSignOnPolicyRules okta.AccessPolicyRule
	resp, err := re.Do(ctx, req, &appSignOnPolicyRules)
	if err != nil {
		return nil, resp, err
	}
	return &appSignOnPolicyRules, resp, nil
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

func (th *TestHarness) CreateIdpDiscoveryRule(ctx context.Context, policyID string, body IdpDiscoveryRule, qp *query.Params) (*IdpDiscoveryRule, *okta.Response, error) {
	re := th.oktaClient.CloneRequestExecutor()
	url := fmt.Sprintf("/api/v1/policies/%s/rules", policyID)
	if qp != nil {
		url += qp.String()
	}
	req, err := re.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, nil, err
	}
	rule := body
	resp, err := re.Do(ctx, req, &rule)
	if err != nil {
		return nil, resp, err
	}
	return &rule, resp, err
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
