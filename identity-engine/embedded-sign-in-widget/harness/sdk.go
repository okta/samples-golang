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

package harness

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

type PolicyRuleCondition struct {
	Key   string   `json:"key"`
	Op    string   `json:"op"`
	Value []string `json:"value"`
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

func (th *TestHarness) fillInOrgInfo() {
	th.org = orgData{}
	groups, _, err := th.oktaClient.Group.ListGroups(context.Background(), &query.Params{Limit: 20})
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	if len(apps) != 1 {
		log.Fatal("more than one app with name 'Golang IDX Web App' exists")
	}
	req, err := th.oktaClient.GetRequestExecutor().NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies?type=Okta:SignOn&resourceId=%s", apps[0].(*okta.Application).Id), nil)
	if err != nil {
		log.Fatal(err)
	}
	var policies []okta.Policy
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &policies)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range policies {
		if v.Name == "Golang IDX Web App" {
			th.org.policyID = v.Id
			break
		}
	}
	req, err = th.oktaClient.GetRequestExecutor().NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/policies/%s/rules", th.org.policyID), nil)
	if err != nil {
		log.Fatal(err)
	}
	var rules []OktaAppSignOnPolicyRule
	_, err = th.oktaClient.GetRequestExecutor().Do(context.Background(), req, &rules)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range rules {
		if v.Name != "MFA Rule" {
			continue
		}
		th.org.mfaRuleID = v.ID
		break
	}
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
	return err
}
