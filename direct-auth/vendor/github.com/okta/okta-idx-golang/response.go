/**
 * Copyright 2020 - Present Okta, Inc.
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

package idx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type Response struct {
	StateHandle                    string                          `json:"stateHandle"`
	Version                        string                          `json:"version"`
	ExpiresAt                      string                          `json:"expiresAt"`
	Intent                         string                          `json:"intent"`
	Remediation                    *Remediation                    `json:"remediation"`
	CancelResponse                 *Option                         `json:"cancel"`
	SuccessResponse                *SuccessOption                  `json:"successWithInteractionCode"`
	CurrentAuthenticatorEnrollment *CurrentAuthenticatorEnrollment `json:"currentAuthenticatorEnrollment"`
	CurrentAuthenticator           *CurrentAuthenticatorEnrollment `json:"currentAuthenticator"`
	Messages                       *Message                        `json:"messages"`
}

type Message struct {
	Type   string         `json:"type"`
	Values []MessageValue `json:"value"`
}

type MessageValue struct {
	Message string           `json:"message"`
	I18N    MessageValueI18N `json:"i18n,omitempty"`
	Class   string           `json:"class"`
}

type MessageValueI18N struct {
	Key string `json:"key"`
}

func (r *Response) UnmarshalJSON(data []byte) error {
	type localIDX Response
	if err := json.Unmarshal(data, (*localIDX)(r)); err != nil {
		return fmt.Errorf("failed to unmarshal Response: %w", err)
	}
	return nil
}

// The method to call when you want to cancel the Okta Identity Engine flow.
// This will return a response for the first step
func (r *Response) Cancel(ctx context.Context) (*Response, error) {
	if r.CancelResponse == nil || len(r.CancelResponse.FormValues) == 0 {
		return nil, errors.New("valid cancel is missing from idx response")
	}
	m := make(map[string]interface{})
	for i := range r.CancelResponse.FormValues {
		m[r.CancelResponse.FormValues[i].Name] = r.CancelResponse.FormValues[i].Value
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cancel request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, r.CancelResponse.Method, r.CancelResponse.Href, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create cancel request: %w", err)
	}
	req.Header.Set("Accepts", r.CancelResponse.Accepts)
	req.Header.Set("Content-Type", r.CancelResponse.Accepts)
	withOktaUserAgent(req)
	resp, err := idx.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %w", err)
	}
	var idxResponse Response
	err = unmarshalResponse(resp, &idxResponse)
	if err != nil {
		return nil, err
	}
	return &idxResponse, nil
}

// get a remediation option by its name
func (r *Response) remediationOption(optionName string) (*RemediationOption, error) {
	if r.Remediation == nil {
		return nil, fmt.Errorf("this response doesn't contain any remediation options")
	}
	for i := range r.Remediation.RemediationOptions {
		if r.Remediation.RemediationOptions[i].Name == optionName {
			return &r.Remediation.RemediationOptions[i], nil
		}
	}
	return nil, fmt.Errorf("could not locate a remediation option with the name '%s'", optionName)
}

// Check for the status of `successWithInteractionCode` indicating if the login was successful.
func (r *Response) LoginSuccess() bool {
	return r.SuccessResponse != nil
}

func (r *Response) authenticatorOption(optionName, label string) (*RemediationOption, string, error) {
	ro, err := r.remediationOption(optionName)
	if err != nil {
		return nil, "", err
	}
	v, err := ro.value("authenticator")
	if err != nil {
		return nil, "", err
	}
	var authID string
	for _, v := range v.Options {
		if v.Label == label {
			authID = v.Value.(FormOptionsValueObject).Form.Value[0].Value
		}
	}
	if authID == "" {
		return nil, "", fmt.Errorf("could not locate authenticator with the '%s' label", label)
	}
	return ro, authID, nil
}
