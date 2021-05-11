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
	"encoding/json"
	"fmt"
	"strings"
)

type ErrorResponse struct {
	ErrorCode        string                   `json:"errorCode,omitempty"`
	ErrorSummary     string                   `json:"errorSummary,omitempty"`
	ErrorLink        string                   `json:"errorLink,omitempty"`
	ErrorID          string                   `json:"errorId,omitempty"`
	ErrorCauses      []map[string]interface{} `json:"errorCauses,omitempty"`
	ErrorType        string                   `json:"error,omitempty"`
	ErrorDescription string                   `json:"error_description,omitempty"`
	Version          string                   `json:"version"`
	Message          Message                  `json:"messages"`
	raw              []byte
}

func (e *ErrorResponse) UnmarshalJSON(data []byte) error {
	type localIDX ErrorResponse
	if err := json.Unmarshal(data, (*localIDX)(e)); err != nil {
		return fmt.Errorf("failed to unmarshal ErrorResponse: %w", err)
	}
	e.raw = data
	return nil
}

func (e *ErrorResponse) Error() string {
	f := "%s"
	switch {
	case e == nil:
		return ""
	case e.ErrorType != "":
		return fmt.Sprintf(f, e.ErrorDescription)
	case len(e.ErrorCauses) > 0:
		causes := make([]string, len(e.ErrorCauses))
		for i := range e.ErrorCauses {
			for key, val := range e.ErrorCauses[i] {
				causes[i] = fmt.Sprintf("%s: %v", key, val)
			}
		}
		return fmt.Sprintf(f+". Causes: %s", e.ErrorSummary, strings.Join(causes, ", "))
	case len(e.Message.Values) > 0:
		messages := make([]string, len(e.Message.Values))
		for i := range e.Message.Values {
			messages[i] = e.Message.Values[i].Message
		}
		return fmt.Sprintf(f, strings.Join(messages, ","))
	default:
		var idxResponse Response
		_ = json.Unmarshal(e.raw, &idxResponse)
		if idxResponse.Remediation != nil {
			for i := range idxResponse.Remediation.RemediationOptions {
				e.Message.Values = append(e.Message.Values, gatherMessages(idxResponse.Remediation.RemediationOptions[i].Form(), e.Message.Values)...)
			}
		}
		if len(e.Message.Values) > 0 {
			messages := make([]string, len(e.Message.Values))
			for i := range e.Message.Values {
				messages[i] = e.Message.Values[i].Message
			}
			return fmt.Sprintf(f, strings.Join(messages, ","))
		}
		return fmt.Sprintf(f, string(e.raw))
	}
}

func gatherMessages(fv []FormValue, messages []MessageValue) []MessageValue {
	if len(fv) == 0 {
		return messages
	}
	for i := range fv {
		if fv[i].Message != nil {
			messages = append(messages, fv[i].Message.Values...)
		}
		if fv[i].Form != nil {
			return gatherMessages(fv[i].Form.FormValues, messages)
		}
	}
	return messages
}
