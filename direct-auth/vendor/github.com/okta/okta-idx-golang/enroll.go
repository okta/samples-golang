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
	"errors"
	"fmt"
	"strings"
)

// EnrollmentResponse is used for the profile enrolment flow.
// It holds the initial IdX context object and the list of the available steps.
// At the end of the successful flow, the only enrollment step will be `EnrollmentStepSuccess`
// and tokens will be available
type EnrollmentResponse struct {
	idxContext     *Context
	token          *Token
	availableSteps []EnrollmentStep
}

// UserProfile holds the necessary information to init the enrollment process.
type UserProfile struct {
	LastName  string `json:"lastName"`
	FirstName string `json:"firstName"`
	Email     string `json:"email"`
}

// InitProfileEnroll starts the enrollment process.
func (c *Client) InitProfileEnroll(ctx context.Context, up *UserProfile) (*EnrollmentResponse, error) {
	idxContext, err := c.interact(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.introspect(ctx, idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("select-enroll-profile")
	if err != nil {
		return nil, err
	}
	resp, err = ro.proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	ro, err = resp.remediationOption("enroll-profile")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(&struct {
		UserProfile *UserProfile `json:"userProfile"`
	}{UserProfile: up})
	resp, err = ro.proceed(ctx, b)
	if err != nil {
		return nil, err
	}
	er := &EnrollmentResponse{
		idxContext: idxContext,
	}
	err = er.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return er, nil
}

// SetNewPassword sets new password for the user.
func (r *EnrollmentResponse) SetNewPassword(ctx context.Context, password string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPasswordSetup) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Password")
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
	ro, err = resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials := []byte(`{
				"credentials": {
					"passcode": "` + strings.TrimSpace(password) + `"
				}
			}`)
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// VerifyEmail sends verification code to the email provided at the first step
func (r *EnrollmentResponse) VerifyEmail(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepEmailVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := verifyEmail(ctx, r.idxContext, "select-authenticator-enroll")
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	r.availableSteps = append(r.availableSteps, EnrollmentStepEmailConfirmation)
	return r, nil
}

// ConfirmEmail confirms email address using the provided code
func (r *EnrollmentResponse) ConfirmEmail(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepEmailConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	return r.confirmWithCode(ctx, code)
}

// PhoneMethod represents the method by which the code will be sent to your phone
type PhoneMethod string

const (
	PhoneMethodVoiceCall PhoneMethod = "voice"
	PhoneMethodSMS       PhoneMethod = "sms"
)

// VerifyPhone sends verification code to the provided phone.
// Your phone number should contain a country code
func (r *EnrollmentResponse) VerifyPhone(ctx context.Context, method PhoneMethod, phoneNumber string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPhoneVerification) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	if method != PhoneMethodVoiceCall && method != PhoneMethodSMS {
		return nil, fmt.Errorf("%s is invalid phone verification method, plese use %s or %s", method, PhoneMethodVoiceCall, PhoneMethodSMS)
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Phone")
	if err != nil {
		return nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `",
					"methodType": "` + string(method) + `",
					"phoneNumber": "` + phoneNumber + `"
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
	r.availableSteps = append(r.availableSteps, EnrollmentStepPhoneConfirmation)
	return r, nil
}

// ConfirmPhone confirms phone number using the provided code
func (r *EnrollmentResponse) ConfirmPhone(ctx context.Context, code string) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepPhoneConfirmation) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	return r.confirmWithCode(ctx, code)
}

// Skip represents general step to proceed with no action
// It usually appears when other steps are optional
func (r *EnrollmentResponse) Skip(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepSkip) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("skip")
	if err != nil {
		return nil, err
	}
	resp, err = ro.proceed(ctx, nil)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Cancel the whole enrollment process.
func (r *EnrollmentResponse) Cancel(ctx context.Context) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepCancel) {
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
	return r, nil
}

// SecurityQuestions represents dict of available security questions.
// Each key represents unique `QuestionKey`, and value represents the human readable question.
type SecurityQuestions map[string]string

// SecurityQuestionOptions returns list of available security questions
func (r *EnrollmentResponse) SecurityQuestionOptions(ctx context.Context) (*EnrollmentResponse, SecurityQuestions, error) {
	if !r.HasStep(EnrollmentStepSecurityQuestionOptions) {
		return nil, nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, nil, err
	}
	ro, authID, err := resp.authenticatorOption("select-authenticator-enroll", "Security Question")
	if err != nil {
		return nil, nil, err
	}
	authenticator := []byte(`{
				"authenticator": {
					"id": "` + authID + `"
				}
			}`)
	resp, err = ro.proceed(ctx, authenticator)
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string)
	ro, err = resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, nil, err
	}
	v, err := ro.value("credentials")
	if err != nil {
		return nil, nil, err
	}
	for i := range v.Options {
		if v.Options[i].Label == "Choose a security question" {
			obj := v.Options[i].Value.(FormOptionsValueObject).Form.Value
			for j := range obj {
				if obj[j].Name == "questionKey" {
					for k := range obj[j].Options {
						m[string(obj[j].Options[k].Value.(FormOptionsValueString))] = obj[j].Options[k].Label
					}
				}
			}
		}
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, nil, err
	}
	r.availableSteps = append(r.availableSteps, EnrollmentStepSecurityQuestionSetup)
	m["custom"] = "Create a security question"
	return r, m, nil
}

// SecurityQuestion represents security question to be used for the account verification.
// In case when 'questionKey'=='custom' the 'question' field should be non-empty and contain custom
// security question.
type SecurityQuestion struct {
	QuestionKey string `json:"questionKey"`
	Question    string `json:"question"`
	Answer      string `json:"answer"`
}

func (r *EnrollmentResponse) SetupSecurityQuestion(ctx context.Context, sq *SecurityQuestion) (*EnrollmentResponse, error) {
	if !r.HasStep(EnrollmentStepSecurityQuestionSetup) {
		return nil, fmt.Errorf("this step is not available, please try one of %s", r.AvailableSteps())
	}
	if sq.QuestionKey == "" {
		return nil, errors.New("missing security question key")
	}
	if sq.Answer == "" {
		return nil, errors.New("missing answer for the security question key")
	}
	if sq.QuestionKey == "custom" && sq.Question == "" {
		return nil, errors.New("missing custom question")
	}
	resp, err := idx.introspect(ctx, r.idxContext.interactionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("enroll-authenticator")
	if err != nil {
		return nil, err
	}
	credentials, _ := json.Marshal(&struct {
		Credentials *SecurityQuestion `json:"credentials"`
	}{Credentials: sq})
	resp, err = ro.proceed(ctx, credentials)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// AvailableSteps returns list of steps that can be executed next.
// In case of successful authentication, list will contain only one "SUCCESS" step.
func (r *EnrollmentResponse) AvailableSteps() []EnrollmentStep {
	return r.availableSteps
}

// HasStep checks if the provided step is present in the list of available steps.
func (r *EnrollmentResponse) HasStep(s EnrollmentStep) bool {
	for i := range r.availableSteps {
		if r.availableSteps[i] == s {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true in case "SUCCESS"is present in the list of available steps.
func (r *EnrollmentResponse) IsAuthenticated() bool {
	return r.HasStep(EnrollmentStepSuccess)
}

// Token returns authorization token. This method should be called when there is "SUCCESS" step
// present in the list of available steps.
func (r *EnrollmentResponse) Token() *Token {
	return r.token
}

type EnrollmentStep int

func (s EnrollmentStep) String() string {
	v, ok := enrollStepText[s]
	if ok {
		return v
	}
	return unknownStep
}

// These codes indicate what method(s) can be called in the next step.
const (
	EnrollmentStepEmailVerification       EnrollmentStep = iota + 1 // 'VerifyEmail'
	EnrollmentStepEmailConfirmation                                 // 'ConfirmEmail'
	EnrollmentStepPasswordSetup                                     // 'SetNewPassword'
	EnrollmentStepPhoneVerification                                 // 'VerifyPhone'
	EnrollmentStepPhoneConfirmation                                 // 'ConfirmPhone'
	EnrollmentStepSecurityQuestionOptions                           // 'SecurityQuestionOptions'
	EnrollmentStepSecurityQuestionSetup                             // 'SetupSecurityQuestion`
	EnrollmentStepCancel                                            // 'Cancel'
	EnrollmentStepSkip                                              // 'Skip'
	EnrollmentStepSuccess                                           // 'Token'
)

var enrollStepText = map[EnrollmentStep]string{
	EnrollmentStepEmailVerification:       "EMAIL_VERIFICATION",
	EnrollmentStepEmailConfirmation:       "EMAIL_CONFIRMATION",
	EnrollmentStepPasswordSetup:           "PASSWORD_SETUP",
	EnrollmentStepPhoneVerification:       "PHONE_VERIFICATION",
	EnrollmentStepPhoneConfirmation:       "PHONE_CONFIRMATION",
	EnrollmentStepSecurityQuestionOptions: "SECURITY_QUESTION_OPTIONS",
	EnrollmentStepSecurityQuestionSetup:   "SECURITY_QUESTION_SETUP",
	EnrollmentStepCancel:                  "CANCEL",
	EnrollmentStepSkip:                    "SKIP",
	EnrollmentStepSuccess:                 "SUCCESS",
}

func (r *EnrollmentResponse) setupNextSteps(ctx context.Context, resp *Response) error {
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
		r.availableSteps = []EnrollmentStep{EnrollmentStepSuccess}
		return nil
	}
	var steps []EnrollmentStep
	if resp.CancelResponse != nil {
		steps = append(steps, EnrollmentStepCancel)
	}
	_, _, err := resp.authenticatorOption("select-authenticator-enroll", "Password")
	if err == nil {
		steps = append(steps, EnrollmentStepPasswordSetup)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Email")
	if err == nil {
		steps = append(steps, EnrollmentStepEmailVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Phone")
	if err == nil {
		steps = append(steps, EnrollmentStepPhoneVerification)
	}
	_, _, err = resp.authenticatorOption("select-authenticator-enroll", "Security Question")
	if err == nil {
		steps = append(steps, EnrollmentStepSecurityQuestionOptions)
	}
	_, err = resp.remediationOption("skip")
	if err == nil {
		steps = append(steps, EnrollmentStepSkip)
	}
	if len(steps) == 0 {
		return fmt.Errorf("there are no more steps available: %v", resp.Messages.Values)
	}
	r.availableSteps = steps
	return nil
}

func (r *EnrollmentResponse) confirmWithCode(ctx context.Context, code string) (*EnrollmentResponse, error) {
	resp, err := passcodeAuth(ctx, r.idxContext, "enroll-authenticator", code)
	if err != nil {
		return nil, err
	}
	err = r.setupNextSteps(ctx, resp)
	if err != nil {
		return nil, err
	}
	return r, nil
}
