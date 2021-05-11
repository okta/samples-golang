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
	"context"
	"encoding/json"
	"fmt"
)

type ResetPasswordResponse struct {
	idxContext     *Context
	token          *Token
	availableSteps []ResetPasswordStep
	sq             *SecurityQuestion
}

type IdentifyRequest struct {
	Identifier  string      `json:"identifier"`
	Credentials Credentials `json:"credentials"`
	RememberMe  bool        `json:"rememberMe"`
}

type Credentials struct {
	Password string `json:"passcode"`
}

func (c *Client) InitPasswordReset(ctx context.Context, ir *IdentifyRequest) (*ResetPasswordResponse, error) {
	idxContext, err := c.interact(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := identifyAndRecover(ctx, idxContext.interactionHandle, ir)
	if err != nil {
		return nil, err
	}
	rpr := &ResetPasswordResponse{
		idxContext: idxContext,
	}
	err = rpr.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return rpr, nil
}

func (r *ResetPasswordResponse) Restart(ctx context.Context, ir *IdentifyRequest) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepRestart) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := identifyAndRecover(ctx, r.idxContext.interactionHandle, ir)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func identifyAndRecover(ctx context.Context, ih *InteractionHandle, ir *IdentifyRequest) (*Response, error) {
	resp, err := idx.introspect(ctx, ih)
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticator != nil {
		resp, err = resp.CurrentAuthenticator.Value.Recover.proceed(ctx, nil)
		if err != nil {
			return nil, err
		}
		var ro *RemediationOption
		ro, err = resp.remediationOption("identify-recovery")
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(ir)
		return ro.proceed(ctx, b)
	}
	ro, err := resp.remediationOption("identify")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(ir)
	resp, err = ro.proceed(ctx, b)
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticatorEnrollment == nil {
		if resp.Messages != nil {
			return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment' "+
				"field is missing from the response: %v", resp.Messages.Values)
		}
		return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment' " +
			"field is missing from the response")
	}
	return resp.CurrentAuthenticatorEnrollment.Value.Recover.proceed(ctx, nil)
}

func (r *ResetPasswordResponse) VerifyEmail(ctx context.Context) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepEmailVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	if resp.CurrentAuthenticatorEnrollment == nil {
		if resp.Messages != nil {
			return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment'"+
				" field is missing from the response: %v", resp.Messages.Values)
		}
		return nil, fmt.Errorf("falied to init password recovery: 'currentAuthenticatorEnrollment'" +
			" field is missing from the response")
	}
	resp, err = resp.CurrentAuthenticatorEnrollment.Value.Recover.proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-authenticate", "Email")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, ResetPasswordStepEmailConfirmation)
	return r, nil
}

func (r *ResetPasswordResponse) ConfirmEmail(ctx context.Context, code string) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepEmailConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	return r.confirmWithCode(ctx, code)
}

func (r *ResetPasswordResponse) AnswerSecurityQuestion(ctx context.Context, answer string) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepAnswerSecurityQuestion) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("challenge-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(fmt.Sprintf(`{
				"credentials": {
					"%s": "%s",
					"answer": "%s"
				}
			}`, questionKey, r.sq.QuestionKey, answer))
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	defer func() { r.sq = nil }() // remove security question to avid confusion
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *ResetPasswordResponse) SetNewPassword(ctx context.Context, password string) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepNewPassword) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := setPassword(ctx, r.idxContext, "reset-authenticator", password)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Cancel the whole reset password process.
func (r *ResetPasswordResponse) Cancel(ctx context.Context) (*ResetPasswordResponse, error) {
	if !r.HasStep(ResetPasswordStepCancel) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	resp, err = resp.Cancel(ctx)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, ResetPasswordStepRestart)
	return r, nil
}

// SecurityQuestion should return SecurityQuestion object in case there is step 'ANSWER SECURITY_QUESTION'
// present in the available steps. It will have non-empty 'questionKey' (unique identifier)
// and 'question' (human readable question) fields
// In case 'ANSWER SECURITY_QUESTION' is not in the list of available steps, response will be nil.
func (r *ResetPasswordResponse) SecurityQuestion() *SecurityQuestion {
	return r.sq
}

// AvailableSteps returns list of steps that can be executed next.
// In case of successful authentication, list will contain only one "SUCCESS" step.
func (r *ResetPasswordResponse) AvailableSteps() []ResetPasswordStep {
	return r.availableSteps
}

// HasStep checks if the provided step is present in the list of available steps.
func (r *ResetPasswordResponse) HasStep(s ResetPasswordStep) bool {
	for i := range r.availableSteps {
		if r.availableSteps[i] == s {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true in case "SUCCESS"is present in the list of available steps.
func (r *ResetPasswordResponse) IsAuthenticated() bool {
	return r.HasStep(ResetPasswordStepSuccess)
}

// Token returns authorization token. This method should be called when there is "SUCCESS" step
// present in the list of available steps.
func (r *ResetPasswordResponse) Token() *Token {
	return r.token
}

type ResetPasswordStep int

func (s ResetPasswordStep) String() string {
	v, ok := resetStepText[s]
	if ok {
		return v
	}
	return unknownStep
}

var resetStepText = map[ResetPasswordStep]string{
	ResetPasswordStepEmailVerification:      "EMAIL_VERIFICATION",
	ResetPasswordStepEmailConfirmation:      "EMAIL_CONFIRMATION",
	ResetPasswordStepAnswerSecurityQuestion: "ANSWER SECURITY_QUESTION",
	ResetPasswordStepNewPassword:            "NEW_PASSWORD",
	ResetPasswordStepCancel:                 "CANCEL",
	ResetPasswordStepRestart:                "RESTART",
	ResetPasswordStepSkip:                   "SKIP",
	ResetPasswordStepSuccess:                "SUCCESS",
}

// These codes indicate what method(s) can be called in the next step.
const (
	ResetPasswordStepEmailVerification      ResetPasswordStep = iota + 1 // 'VerifyEmail'
	ResetPasswordStepEmailConfirmation                                   // 'ConfirmEmail'
	ResetPasswordStepAnswerSecurityQuestion                              // 'AnswerSecurityQuestion'
	ResetPasswordStepNewPassword                                         // 'SetNewPassword'
	ResetPasswordStepCancel                                              // 'Cancel'
	ResetPasswordStepRestart                                             // 'Restart'
	ResetPasswordStepSkip                                                // 'Skip'
	ResetPasswordStepSuccess                                             // 'Token'
)

const (
	questionKey = "questionKey"
	unknownStep = "UNKNOWN"
)

// nolint
func (r *ResetPasswordResponse) setupNextSteps(ctx context.Context, resp *Response) error {
	if resp.LoginSuccess() {
		exchangeForm := []byte(`{
			"client_secret": "` + idx.ClientSecret() + `",
			"code_verifier": "` + r.idxContext.codeVerifier + `"
		}`)
		tokens, err := resp.SuccessResponse.exchangeCode(ctx, exchangeForm)
		if err != nil {
			return err
		}
		r.token = tokens
		r.availableSteps = []ResetPasswordStep{ResetPasswordStepSuccess}
		return nil
	}
	var steps []ResetPasswordStep
	if resp.CancelResponse != nil {
		steps = append(steps, ResetPasswordStepCancel)
	}
	_, _, err := resp.authenticatorOption("select-authenticator-authenticate", "Email")
	if err == nil {
		steps = append(steps, ResetPasswordStepEmailVerification)
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		steps = append(steps, ResetPasswordStepSkip)
	}
	ro, err := resp.remediationOption("challenge-authenticator")
	if err == nil {
	loop:
		for i := range ro.FormValues {
			if ro.FormValues[i].Form != nil && len(ro.FormValues[i].Form.FormValues) > 0 {
				for j := range ro.FormValues[i].Form.FormValues {
					if ro.FormValues[i].Form.FormValues[j].Name == questionKey {
						r.sq = &SecurityQuestion{
							QuestionKey: ro.FormValues[i].Form.FormValues[j].Value,
							Question:    ro.FormValues[i].Form.FormValues[j].Label,
						}
						steps = append(steps, ResetPasswordStepAnswerSecurityQuestion)
						break loop
					}
				}
			}
		}
	}
	ro, err = resp.remediationOption("reset-authenticator")
	if err == nil {
	loop2:
		for i := range ro.FormValues {
			if ro.FormValues[i].Form != nil && len(ro.FormValues[i].Form.FormValues) > 0 {
				for j := range ro.FormValues[i].Form.FormValues {
					if ro.FormValues[i].Form.FormValues[j].Label == "New password" {
						steps = append(steps, ResetPasswordStepNewPassword)
						break loop2
					}
				}
			}
		}
	}
	if len(steps) == 0 {
		return fmt.Errorf("there are no more steps available: %v", resp.Messages.Values)
	}
	r.availableSteps = steps
	return nil
}

func (r *ResetPasswordResponse) confirmWithCode(ctx context.Context, code string) (*ResetPasswordResponse, error) {
	resp, err := passcodeAuth(ctx, r.idxContext, "challenge-authenticator", code)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	return r, err
}
