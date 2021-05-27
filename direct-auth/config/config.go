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

package config

import (
	"errors"
	"fmt"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/spf13/viper"
)

type Config struct {
	Okta struct {
		IDX struct {
			ClientID     string   `mapstructure:"clientId" schema:"client_id"`
			ClientSecret string   `mapstructure:"clientSecret" schema:"client_secret"`
			Issuer       string   `mapstructure:"issuer" schema:"-"`
			Scopes       []string `mapstructure:"scopes" schema:"scope"`
			RedirectURI  string   `mapstructure:"redirectUri" schema:"redirect_uri"`
		} `mapstructure:"idx"`
	} `mapstructure:"okta"`
	Testing bool
}

func (c *Config) Validate() error {
	return validation.ValidateStruct(&c.Okta.IDX,
		validation.Field(&c.Okta.IDX.ClientID, validation.Required),
		validation.Field(&c.Okta.IDX.ClientSecret, validation.Required),
		validation.Field(&c.Okta.IDX.Issuer, validation.Required),
		validation.Field(&c.Okta.IDX.Scopes, validation.Required),
		validation.Field(&c.Okta.IDX.RedirectURI, validation.Required),
	)
}

// ReadConfig reads config from file and environment variables
// Config file should be placed either in project root dir or in $HOME/.okta/
// If no config file provided, you should use ConfigSetters to set config
func ReadConfig(config interface{}, opts ...viper.DecoderConfigOption) error {
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
