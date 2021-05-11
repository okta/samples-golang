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
	"errors"
	"fmt"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/spf13/viper"
)

type config struct {
	Okta struct {
		IDX struct {
			ClientID     string   `mapstructure:"clientId" schema:"client_id"`
			ClientSecret string   `mapstructure:"clientSecret" schema:"client_secret"`
			Issuer       string   `mapstructure:"issuer" schema:"-"`
			Scopes       []string `mapstructure:"scopes" schema:"scope"`
			RedirectURI  string   `mapstructure:"redirectUri" schema:"redirect_uri"`
		} `mapstructure:"idx"`
	} `mapstructure:"okta"`
}

func (c config) Validate() error {
	return validation.ValidateStruct(&c.Okta.IDX,
		validation.Field(&c.Okta.IDX.ClientID, validation.Required),
		validation.Field(&c.Okta.IDX.ClientSecret, validation.Required),
		validation.Field(&c.Okta.IDX.Issuer, validation.Required),
		validation.Field(&c.Okta.IDX.Scopes, validation.Required),
		validation.Field(&c.Okta.IDX.RedirectURI, validation.Required),
	)
}

type ConfigSetter func(*config)

func WithClientID(clientID string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.ClientID = clientID
	}
}

func WithClientSecret(clientSecret string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.ClientSecret = clientSecret
	}
}

func WithIssuer(issuer string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.Issuer = issuer
	}
}

func WithScopes(scopes []string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.Scopes = scopes
	}
}

func WithRedirectURI(redirectURI string) ConfigSetter {
	return func(c *config) {
		c.Okta.IDX.RedirectURI = redirectURI
	}
}

// readConfig reads config from file and environment variables
// Config file should be placed either in project root dir or in $HOME/.okta/
// If no config file provided, you should use ConfigSetters to set config
func readConfig(config interface{}, opts ...viper.DecoderConfigOption) error {
	v := viper.New()
	v.SetConfigName("okta")
	v.AddConfigPath("$HOME/.okta/")                    // path to look for the config file in
	v.AddConfigPath(".")                               // path to look for config in the working directory
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // replace default viper delimiter for env vars
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)
	err := v.ReadInConfig()
	if err != nil {
		var vErr viper.ConfigFileNotFoundError
		if !errors.As(err, &vErr) { // skip reading from file if it's not present
			return fmt.Errorf("failed to read from config file: %w", err)
		}
	}
	err = v.Unmarshal(config, opts...)
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	return nil
}
