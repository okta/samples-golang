package harness

import (
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
)

type Policy struct {
	Embedded    interface{}                `json:"_embedded,omitempty"`
	Links       interface{}                `json:"_links,omitempty"`
	Conditions  *okta.PolicyRuleConditions `json:"conditions,omitempty"`
	Created     *time.Time                 `json:"created,omitempty"`
	Description string                     `json:"description,omitempty"`
	Id          string                     `json:"id,omitempty"`
	LastUpdated *time.Time                 `json:"lastUpdated,omitempty"`
	Name        string                     `json:"name,omitempty"`
	Priority    int64                      `json:"priority,omitempty"`
	Status      string                     `json:"status,omitempty"`
	System      *bool                      `json:"system,omitempty"`
	Type        string                     `json:"type,omitempty"`
	Settings    *PolicySettings            `json:"settings,omitempty"`
}

type T struct {
	Settings struct {
		Type           string `json:"type"`
		Authenticators []struct {
		} `json:"authenticators"`
	} `json:"settings"`
}

type PolicySettings struct {
	Factors        *PolicyFactorsSettings                 `json:"factors,omitempty"`
	Delegation     *okta.PasswordPolicyDelegationSettings `json:"delegation,omitempty"`
	Password       *PasswordPolicyPasswordSettings        `json:"password,omitempty"`
	Recovery       *PasswordPolicyRecoverySettings        `json:"recovery,omitempty"`
	Type           string                                 `json:"type"`
	Authenticators []PolicySettingsAuthenticator          `json:"authenticators"`
}

type PolicySettingsAuthenticator struct {
	Key    string                            `json:"key"`
	Enroll PolicySettingsAuthenticatorEnroll `json:"enroll"`
}

type PolicySettingsAuthenticatorEnroll struct {
	Self string `json:"self"`
}

type PasswordPolicyPasswordSettings struct {
	Age        *PasswordPolicyPasswordSettingsAge        `json:"age,omitempty"`
	Complexity *PasswordPolicyPasswordSettingsComplexity `json:"complexity,omitempty"`
	Lockout    *PasswordPolicyPasswordSettingsLockout    `json:"lockout,omitempty"`
}

type PasswordPolicyPasswordSettingsAge struct {
	ExpireWarnDays int64 `json:"expireWarnDays"`
	HistoryCount   int64 `json:"historyCount"`
	MaxAgeDays     int64 `json:"maxAgeDays"`
	MinAgeMinutes  int64 `json:"minAgeMinutes"`
}

type PasswordPolicyPasswordSettingsComplexity struct {
	Dictionary        *okta.PasswordDictionary `json:"dictionary,omitempty"`
	ExcludeAttributes []string                 `json:"excludeAttributes,omitempty"`
	ExcludeUsername   *bool                    `json:"excludeUsername,omitempty"`
	MinLength         int64                    `json:"minLength"`
	MinLowerCase      int64                    `json:"minLowerCase"`
	MinNumber         int64                    `json:"minNumber"`
	MinSymbol         int64                    `json:"minSymbol"`
	MinUpperCase      int64                    `json:"minUpperCase"`
}

type PasswordPolicyRecoverySettings struct {
	Factors *PasswordPolicyRecoveryFactors `json:"factors,omitempty"`
}

type PasswordPolicyRecoveryFactors struct {
	OktaCall         *okta.PasswordPolicyRecoveryFactorSettings `json:"okta_call,omitempty"`
	OktaSms          *okta.PasswordPolicyRecoveryFactorSettings `json:"okta_sms,omitempty"`
	OktaEmail        *PasswordPolicyRecoveryEmail               `json:"okta_email,omitempty"`
	RecoveryQuestion *PasswordPolicyRecoveryQuestion            `json:"recovery_question,omitempty"`
}

type PasswordPolicyRecoveryEmail struct {
	Properties *PasswordPolicyRecoveryEmailProperties `json:"properties,omitempty"`
	Status     string                                 `json:"status,omitempty"`
}

type PasswordPolicyRecoveryEmailProperties struct {
	RecoveryToken *PasswordPolicyRecoveryEmailRecoveryToken `json:"recoveryToken,omitempty"`
}

type PasswordPolicyRecoveryEmailRecoveryToken struct {
	TokenLifetimeMinutes int64 `json:"tokenLifetimeMinutes"`
}

type PasswordPolicyRecoveryQuestion struct {
	Properties *PasswordPolicyRecoveryQuestionProperties `json:"properties,omitempty"`
	Status     string                                    `json:"status,omitempty"`
}

type PasswordPolicyRecoveryQuestionProperties struct {
	Complexity *PasswordPolicyRecoveryQuestionComplexity `json:"complexity,omitempty"`
}

type PasswordPolicyPasswordSettingsLockout struct {
	AutoUnlockMinutes               int64    `json:"autoUnlockMinutes"`
	MaxAttempts                     int64    `json:"maxAttempts"`
	ShowLockoutFailures             *bool    `json:"showLockoutFailures,omitempty"`
	UserLockoutNotificationChannels []string `json:"userLockoutNotificationChannels,omitempty"`
}

type PasswordPolicyRecoveryQuestionComplexity struct {
	MinLength int64 `json:"minLength"`
}

type PolicyFactorsSettings struct {
	Duo          *PolicyFactor `json:"duo,omitempty"`
	FidoU2f      *PolicyFactor `json:"fido_u2f,omitempty"`
	FidoWebauthn *PolicyFactor `json:"fido_webauthn,omitempty"`
	GoogleOtp    *PolicyFactor `json:"google_otp,omitempty"`
	OktaCall     *PolicyFactor `json:"okta_call,omitempty"`
	OktaOtp      *PolicyFactor `json:"okta_otp,omitempty"`
	OktaPassword *PolicyFactor `json:"okta_password,omitempty"`
	OktaPush     *PolicyFactor `json:"okta_push,omitempty"`
	OktaQuestion *PolicyFactor `json:"okta_question,omitempty"`
	OktaSms      *PolicyFactor `json:"okta_sms,omitempty"`
	OktaEmail    *PolicyFactor `json:"okta_email,omitempty"`
	RsaToken     *PolicyFactor `json:"rsa_token,omitempty"`
	SymantecVip  *PolicyFactor `json:"symantec_vip,omitempty"`
	YubikeyToken *PolicyFactor `json:"yubikey_token,omitempty"`
	Hotp         *PolicyFactor `json:"hotp,omitempty"`
}

type PolicyFactor struct {
	Consent *Consent `json:"consent,omitempty"`
	Enroll  *Enroll  `json:"enroll,omitempty"`
}

type Consent struct {
	Terms *Terms `json:"terms,omitempty"`
	Type  string `json:"type,omitempty"`
}

type Terms struct {
	Format string `json:"format,omitempty"`
	Value  string `json:"value,omitempty"`
}

type Enroll struct {
	Self string `json:"self,omitempty"`
}

type (
	IdpDiscoveryRuleActions struct {
		IDP *IdpDiscoveryRuleIdp `json:"idp"`
	}

	IdpDiscoveryRuleApp struct {
		Exclude []*IdpDiscoveryRuleAppObj `json:"exclude"`
		Include []*IdpDiscoveryRuleAppObj `json:"include"`
	}

	IdpDiscoveryRuleAppObj struct {
		Type string `json:"type,omitempty"`
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	}

	IdpDiscoveryRuleConditions struct {
		App            *IdpDiscoveryRuleApp            `json:"app"`
		Network        *IdpDiscoveryRuleNetwork        `json:"network"`
		Platform       *IdpDiscoveryRulePlatform       `json:"platform,omitempty"`
		UserIdentifier *IdpDiscoveryRuleUserIdentifier `json:"userIdentifier,omitempty"`
	}

	IdpDiscoveryRuleIdp struct {
		Providers []*IdpDiscoveryRuleProvider `json:"providers"`
	}

	IdpDiscoveryRuleNetwork struct {
		Connection string   `json:"connection,omitempty"`
		Include    []string `json:"include,omitempty"`
		Exclude    []string `json:"exclude,omitempty"`
	}

	IdpDiscoveryRulePattern struct {
		MatchType string `json:"matchType,omitempty"`
		Value     string `json:"value,omitempty"`
	}

	IdpDiscoveryRulePlatformOS struct {
		Type       string `json:"type,omitempty"`
		Expression string `json:"expression,omitempty"`
	}

	IdpDiscoveryRulePlatformInclude struct {
		Os   *IdpDiscoveryRulePlatformOS `json:"os"`
		Type string                      `json:"type,omitempty"`
	}

	IdpDiscoveryRulePlatform struct {
		Exclude []interface{}                      `json:"exclude,omitempty"`
		Include []*IdpDiscoveryRulePlatformInclude `json:"include,omitempty"`
	}

	IdpDiscoveryRuleProvider struct {
		Type string `json:"type,omitempty"`
		ID   string `json:"id,omitempty"`
	}

	IdpDiscoveryRuleUserIdentifier struct {
		Attribute string                     `json:"attribute,omitempty"`
		Patterns  []*IdpDiscoveryRulePattern `json:"patterns,omitempty"`
		Type      string                     `json:"type,omitempty"`
	}

	IdpDiscoveryRule struct {
		Actions     *IdpDiscoveryRuleActions    `json:"actions,omitempty"`
		Conditions  *IdpDiscoveryRuleConditions `json:"conditions,omitempty"`
		Created     string                      `json:"created,omitempty"`
		ID          string                      `json:"id,omitempty"`
		LastUpdated string                      `json:"lastUpdated,omitempty"`
		Name        string                      `json:"name,omitempty"`
		Priority    int                         `json:"priority,omitempty"`
		Status      string                      `json:"status,omitempty"`
		System      bool                        `json:"system,omitempty"`
		Type        string                      `json:"type,omitempty"`
		MultiIdpIds bool                        `json:"multiIdpIds"`
	}
)
type T2 struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Conditions struct {
		Network struct {
			Connection string `json:"connection"`
		} `json:"network"`
		App struct {
			Include []struct {
				Type string `json:"type"`
				Id   string `json:"id"`
			} `json:"include"`
			Exclude []interface{} `json:"exclude"`
		} `json:"app"`
		Platform struct {
			Include []struct {
				Type string `json:"type"`
				Os   struct {
					Type string `json:"type"`
				} `json:"os"`
			} `json:"include"`
			Exclude []interface{} `json:"exclude"`
		} `json:"platform"`
		UserIdentifier struct {
			Type     interface{}   `json:"type"`
			Patterns []interface{} `json:"patterns"`
		} `json:"userIdentifier"`
	} `json:"conditions"`
	Actions struct {
		Idp struct {
			Providers []struct {
				Type string `json:"type,omitempty"`
				Id   string `json:"id,omitempty"`
			} `json:"providers"`
		} `json:"idp"`
	} `json:"actions"`
	MultiIdpIds bool `json:"multiIdpIds"`
}
