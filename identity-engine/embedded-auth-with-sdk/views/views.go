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
	"net/http"
	"reflect"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/config"
)

var (
	tpl *template.Template
	cfg *config.Config
)

type ViewConfig struct {
	config      *config.Config
	session     *sessions.CookieStore
	currRequest *http.Request
}

func NewView(c *config.Config, s *sessions.CookieStore) *ViewConfig {
	return &ViewConfig{
		config:  c,
		session: s,
	}
}

func (vc *ViewConfig) TemplateFuncs() template.FuncMap {
	cfg = vc.config

	return template.FuncMap{
		"configOption": configOption,
	}
}

func configOption(item string) string {
	if item == "Scopes" {
		return strings.Join(cfg.Okta.IDX.Scopes, ", ")
	}

	if item == "ClientSecret" {
		return "****" + string(cfg.Okta.IDX.ClientSecret[len(cfg.Okta.IDX.ClientSecret)-7:])
	}

	r := reflect.ValueOf(cfg.Okta.IDX)
	f := reflect.Indirect(r).FieldByName(item)
	return string(f.String())
}
