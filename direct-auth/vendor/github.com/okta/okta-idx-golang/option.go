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
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

type Remediation struct {
	Type               string              `json:"type"`
	RemediationOptions []RemediationOption `json:"value"`
}

type Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

// Allow you to continue the remediation with this option.
type Option struct {
	Rel        []string    `json:"rel"`
	Name       string      `json:"name"`
	Href       string      `json:"href"`
	Method     string      `json:"method"`
	FormValues []FormValue `json:"value"`
	Accepts    string      `json:"accepts"`
}

type FormValue struct {
	Name     string        `json:"name"`
	Label    string        `json:"label,omitempty"`
	Type     string        `json:"type,omitempty"`
	Value    string        `json:"value,omitempty"`
	Required *bool         `json:"required,omitempty"`
	Visible  *bool         `json:"visible,omitempty"`
	Mutable  *bool         `json:"mutable,omitempty"`
	Secret   *bool         `json:"secret,omitempty"`
	Form     *Form         `json:"form,omitempty"`
	Options  []FormOptions `json:"options,omitempty"`
	Message  *Message      `json:"messages"`
}

type Form struct {
	FormValues []FormValue `json:"value"`
}

type FormOptions struct {
	Label        string           `json:"label"`
	Value        FormOptionsValue `json:"-"`
	DynamicValue interface{}      `json:"value"`
	RelatesTo    string           `json:"relatesTo"`
}

func (r *FormOptions) UnmarshalJSON(data []byte) error {
	type localIDX FormOptions
	r.Value = FormOptionsValueObject{}
	if err := json.Unmarshal(data, (*localIDX)(r)); err != nil {
		return fmt.Errorf("failed to unmarshal FormOptions: %w", err)
	}
	switch dv := r.DynamicValue.(type) {
	case string:
		r.Value = FormOptionsValueString(dv)
	case map[string]interface{}:
		b, _ := json.Marshal(dv)
		var res FormOptionsValueObject
		_ = json.Unmarshal(b, &res)
		r.Value = res
	}
	return nil
}

type FormOptionsValue interface {
	isFormOptionsValue()
}

type FormOptionsValueString string

func (FormOptionsValueString) isFormOptionsValue() {}

type FormOptionsValueObject struct {
	Form FormOptionsValueForm `json:"form"`
}

func (FormOptionsValueObject) isFormOptionsValue() {}

type FormOptionsValueForm struct {
	Value []FormValue `json:"value"`
}

type RemediationOption Option

// Form gets all form values
func (o *RemediationOption) Form() []FormValue {
	if o == nil {
		return nil
	}
	return o.FormValues
}

func (o *Option) proceed(ctx context.Context, data []byte) (*Response, error) {
	if o == nil || len(o.FormValues) == 0 {
		return nil, errors.New("valid proceed is missing from idx response")
	}
	input := make(map[string]interface{})
	if len(data) != 0 {
		err := json.Unmarshal(data, &input)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal input data: %w", err)
		}
	}
	output, err := form(input, nil, o.FormValues...)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(&output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proceed request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, o.Method, o.Href, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create cancel request: %w", err)
	}
	req.Header.Set("Accepts", o.Accepts)
	req.Header.Set("Content-Type", o.Accepts)
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

// proceed allows you to continue the remediation with this option.
// It will return error when provided data does not contain all required values to proceed call.
// Data should be in JSON format.
func (o *RemediationOption) proceed(ctx context.Context, data []byte) (*Response, error) {
	op := Option(*o)
	return op.proceed(ctx, data)
}

func (o *RemediationOption) value(name string) (*FormValue, error) {
	for i := range o.FormValues {
		if o.FormValues[i].Name == name {
			return &o.FormValues[i], nil
		}
	}
	return nil, fmt.Errorf("could not locate a form value with the name '%s'", name)
}

//nolint
func form(input, output map[string]interface{}, f ...FormValue) (map[string]interface{}, error) {
	if output == nil {
		output = make(map[string]interface{})
	}
	for _, v := range f {
		switch {
		case v.Value != "":
			output[v.Name] = v.Value
		case v.Value == "" && v.Form == nil && len(v.Options) == 0:
			vv, ok := input[v.Name]
			if ok {
				output[v.Name] = vv
			}
			if !ok && v.Required != nil && *v.Required {
				return nil, fmt.Errorf("missing '%s' property from input", v.Name)
			}
		case v.Form != nil && len(v.Form.FormValues) != 0:
			vv, ok := input[v.Name]
			if !ok && v.Required != nil && *v.Required {
				return nil, fmt.Errorf("missing '%s' property from input", v.Name)
			}
			if !ok {
				continue
			}
			im, ok := vv.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s should be of type map[string]interface{}, got: %T", v.Name, vv)
			}
			var err error
			output[v.Name] = map[string]interface{}{}
			output[v.Name], err = form(im, output[v.Name].(map[string]interface{}), v.Form.FormValues...)
			if err != nil {
				return nil, err
			}
		case len(v.Options) != 0:
			if v.Type == "string" {
				vv, ok := input[v.Name]
				if !ok && v.Required != nil && *v.Required {
					return nil, fmt.Errorf("missing '%s' property from input", v.Name)
				}
				strVal, ok := vv.(string)
				if !ok {
					return nil, fmt.Errorf("%s should be of type string, got: %T", v.Name, vv)
				}
				presentInOptions := false
				for _, o := range v.Options {
					if strVal == string(o.Value.(FormOptionsValueString)) {
						presentInOptions = true
						break
					}
				}
				if !presentInOptions {
					return nil, fmt.Errorf("provided value '%s' for '%s' is missing from options", vv, v.Name)
				}
				output[v.Name] = vv
			} else if v.Type == "object" {
				vv, ok := input[v.Name]
				for _, o := range v.Options {
					for _, vfv := range o.Value.(FormOptionsValueObject).Form.Value {
						if !ok && vfv.Required != nil && *vfv.Required && vfv.Value == "" {
							return nil, fmt.Errorf("missing '%s.%s' property from input", v.Name, vfv.Name)
						}
					}
				}
				var im map[string]interface{}
				if ok {
					im, ok = vv.(map[string]interface{})
					if !ok {
						return nil, fmt.Errorf("%s should be of type map[string]interface{}, got: %T", v.Name, vv)
					}
				}
				var err error
				gg := map[string]interface{}{}
			loop:
				for _, o := range v.Options {
					for _, a := range o.Value.(FormOptionsValueObject).Form.Value {
						n, ok := im[a.Name]
						if !ok || (a.Value != "" && !reflect.DeepEqual(n, a.Value)) {
							continue
						}
						gg, err = form(im, gg, o.Value.(FormOptionsValueObject).Form.Value...)
						if err != nil {
							return nil, err
						}
						output[v.Name] = gg
						break loop
					}
				}
			}
		}
	}
	return output, nil
}

type SuccessOption Option

// Exchange the code from SuccessWithInteractionCode
func (o *SuccessOption) exchangeCode(ctx context.Context, data []byte) (*Token, error) {
	if o == nil || len(o.FormValues) == 0 {
		return nil, errors.New("valid success response is missing from idx response")
	}
	input := make(map[string]interface{})
	err := json.Unmarshal(data, &input)
	if err != nil {
		return nil, fmt.Errorf("failed to input data: %w", err)
	}
	output, err := form(input, nil, o.FormValues...)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if strings.Contains(o.Accepts, "x-www-form-urlencoded") {
		data := url.Values{}
		for k, v := range output {
			switch val := v.(type) {
			case string:
				data[k] = []string{val}
			case *string:
				data[k] = []string{*val}
			default:
				return nil, fmt.Errorf("%s should be of type string, got: %T", k, v)
			}
		}
		body = strings.NewReader(data.Encode())
	} else {
		b, _ := json.Marshal(&output)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, o.Method, o.Href, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create interact http request: %w", err)
	}
	req.Header.Set("Accepts", o.Accepts)
	req.Header.Set("Content-Type", o.Accepts)
	withOktaUserAgent(req)
	resp, err := idx.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call has failed: %w", err)
	}
	var token Token
	err = unmarshalResponse(resp, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

type RecoverOption Option

type CurrentAuthenticatorEnrollment struct {
	Type  string `json:"type"`
	Value struct {
		Recover     *RecoverOption `json:"recover"`
		Type        string         `json:"type"`
		Key         string         `json:"key"`
		ID          string         `json:"id"`
		DisplayName string         `json:"displayName"`
		Methods     []struct {
			Type string `json:"type"`
		} `json:"methods"`
	} `json:"value"`
}

// proceed allows you to continue the remediation with this option.
// It will return error when provided data does not contain all required values to proceed call.
// Data should be in JSON format.
func (o *RecoverOption) proceed(ctx context.Context, data []byte) (*Response, error) {
	op := Option(*o)
	return op.proceed(ctx, data)
}
