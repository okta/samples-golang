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

package views

import (
	"html/template"
	"reflect"
	"strings"

	"github.com/gorilla/sessions"

	idx "github.com/okta/okta-idx-golang"
)

var (
	idxClient *idx.Client
)

type ViewConfig struct {
	session *sessions.CookieStore
}

func NewView(c *idx.Client, s *sessions.CookieStore) *ViewConfig {
	idxClient = c
	return &ViewConfig{
		session: s,
	}
}

func (vc *ViewConfig) TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"configOption": configOption,
	}
}

func configOption(item string) string {
	if item == "Scopes" {
		return strings.Join(idxClient.Config().Okta.IDX.Scopes, ", ")
	}

	if item == "ClientSecret" {
		secret := idxClient.Config().Okta.IDX.ClientSecret
		return "****" + string(secret[len(secret)-7:])
	}

	r := reflect.ValueOf(idxClient.Config().Okta.IDX)
	f := reflect.Indirect(r).FieldByName(item)
	return string(f.String())
}
