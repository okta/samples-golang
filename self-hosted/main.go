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

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/spf13/viper"
)

var tpl *template.Template
var sessionStoreName = "okta-self-hosted-session-store"
var sessionKey = "randomKey"
var sessionStore = sessions.NewCookieStore([]byte(sessionKey))
var state = "ApplicationState"
var nonce = "NonceNotSetYet"
var cfg = &config{}
var pkce *PKCE

type PKCE struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

func init() {

	tpl = template.Must(template.ParseGlob("templates/*"))

	err := ReadConfig(cfg)
	if err != nil {
		fmt.Printf("failed to read config: %s\n", err.Error())
		os.Exit(1)
	}

}
func createCodeVerifier() (*string, error) {
	codeVerifier := make([]byte, 86)
	_, err := rand.Read(codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("error creating code_verifier: %w", err)
	}

	s := base64.RawURLEncoding.EncodeToString(codeVerifier)
	return &s, nil
}

func createPKCEData() (*PKCE, error) {
	h := sha256.New()

	codeVerifier, err := createCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create codeVerifier: %w", err)
	}

	_, err = h.Write([]byte(*codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("failed to write codeVerifier: %w", err)
	}

	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return &PKCE{
		CodeChallenge:       codeChallenge,
		CodeVerifier:        *codeVerifier,
		CodeChallengeMethod: "S256",
	}, nil

}

func main() {
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/login/callback", LoginCallbackHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)

	log.Print("server starting at localhost:8080 ... ")
	err := http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s\n", err)
		os.Exit(1)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	type customData struct {
		Profile         map[string]string
		IsAuthenticated bool
	}

	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
	}

	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	session, err := sessionStore.Get(r, sessionStoreName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if session.Values["pkceData"] == nil || session.Values["pkceData"] == "" {
		pkce, err = createPKCEData()
		if err != nil {
			fmt.Printf("could not create pkce data: %s\n", err.Error())
			os.Exit(1)
		}
		session.Values["pkce_code_verifier"] = pkce.CodeVerifier
		session.Values["pkce_code_challenge"] = pkce.CodeChallenge
		session.Values["pkce_code_challenge_method"] = pkce.CodeChallengeMethod
		session.Save(r, w)
	} else {
		pkce.CodeVerifier = session.Values["pkce_code_verifier"].(string)
		pkce.CodeChallenge = session.Values["pkce_code_challenge"].(string)
		pkce.CodeChallengeMethod = session.Values["pkce_code_challenge_method"].(string)
	}
	log.Printf("%+v\n", session.Values)
	nonce, err := generateNonce()
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		os.Exit(1)
	}
	type customData struct {
		IsAuthenticated   bool
		BaseUrl           string
		ClientId          string
		Issuer            string
		State             string
		Nonce             string
		InteractionHandle string
		Pkce              *PKCE
	}

	interactionHandle, err := getInteractionHandle(pkce.CodeChallenge)
	if err != nil {
		fmt.Printf("could not get interactionHandle: %s\n", err.Error())
	}
	issuerParts, err := url.Parse(cfg.Okta.IDX.Issuer)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		os.Exit(1)
	}
	baseUrl := issuerParts.Scheme + "://" + issuerParts.Hostname()

	data := customData{
		IsAuthenticated:   isAuthenticated(r),
		BaseUrl:           baseUrl,
		ClientId:          cfg.Okta.IDX.ClientID,
		Issuer:            cfg.Okta.IDX.Issuer,
		State:             state,
		Nonce:             nonce,
		Pkce:              pkce,
		InteractionHandle: interactionHandle,
	}
	err = tpl.ExecuteTemplate(w, "login.gohtml", data)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
	}
}

func LoginCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != state {
		fmt.Fprintln(w, "The state was not as expected")
		return
	}
	// Make sure the interaction_code was provided
	if r.URL.Query().Get("interaction_code") == "" {
		fmt.Fprintln(w, "The interaction_code was not returned or is not accessible")
		return
	}

	session, err := sessionStore.Get(r, sessionStoreName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	//log.Printf("%+v\n", session.Values)
	if session.Values["pkce_code_verifier"] == nil ||
		session.Values["pkce_code_verifier"] == "" ||
		session.Values["pkce_code_challenge"] == nil ||
		session.Values["pkce_code_challenge"] == "" ||
		session.Values["pkce_code_challenge_method"] == nil ||
		session.Values["pkce_code_challenge_method"] == "" {
		fmt.Fprintln(w, "Could not get PKCE Data from session")
		return
	}
	q := r.URL.Query()
	q.Del("state")

	q.Add("grant_type", "interaction_code")
	q.Set("interaction_code", r.URL.Query().Get("interaction_code"))
	q.Add("client_id", cfg.Okta.IDX.ClientID)
	q.Add("client_secret", cfg.Okta.IDX.ClientSecret)
	q.Add("code_verifier", session.Values["pkce_code_verifier"].(string))

	url := cfg.Okta.IDX.Issuer + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("RESP ERROR: %+v\n", err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("READ ERROR: %+v\n", err.Error())
	}
	defer resp.Body.Close()

	var exchange Exchange
	err = json.Unmarshal(body, &exchange)
	if err != nil {
		log.Fatalf("UNMARSHAL ERROR: %+v\n", err.Error())
	}

	_, verificationError := verifyToken(exchange.IdToken)

	if verificationError != nil {
		log.Fatalf("Verification Error: %+v\n", verificationError)
	}

	session.Values["id_token"] = exchange.IdToken
	session.Values["access_token"] = exchange.AccessToken

	err = session.Save(r, w)
	if err != nil {
		log.Fatalf("SESSION SAVE ERROR: %+v\n", err.Error())
	}

	http.Redirect(w, r, "/", http.StatusFound)

}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, sessionStoreName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	type customData struct {
		Profile         map[string]string
		IsAuthenticated bool
	}

	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
	}
	tpl.ExecuteTemplate(w, "profile.gohtml", data)
}

func getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, sessionStoreName)

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := cfg.Okta.IDX.Issuer + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["aud"] = cfg.Okta.IDX.ClientID
	jv := verifier.JwtVerifier{
		Issuer:           cfg.Okta.IDX.Issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)

	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

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

func ReadConfig(c *config, opts ...viper.DecoderConfigOption) error {
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
	err = v.Unmarshal(c, opts...)
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	return nil
}

func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func printcURL(req *http.Request) error {
	var (
		command string
		b       []byte
		err     error
	)
	if req.URL != nil {
		command = fmt.Sprintf("curl -X %s '%s'", req.Method, req.URL.String())
	}
	for k, v := range req.Header {
		command += fmt.Sprintf(" -H '%s: %s'", k, strings.Join(v, ", "))
	}
	if req.Body != nil {
		b, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
		command += fmt.Sprintf(" -d %q", string(b))
	}
	fmt.Fprintf(os.Stderr, "cURL Command: %s\n", command)
	// reset body
	body := bytes.NewBuffer(b)
	req.Body = ioutil.NopCloser(body)
	return nil
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, sessionStoreName)

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func getInteractionHandle(codeChallenge string) (string, error) {
	data := url.Values{}
	data.Set("client_id", cfg.Okta.IDX.ClientID)
	data.Set("scope", strings.Join(cfg.Okta.IDX.Scopes, " "))
	data.Set("code_challenge", codeChallenge)
	data.Set("code_challenge_method", "S256")
	data.Set("redirect_uri", cfg.Okta.IDX.RedirectURI)
	data.Set("state", state)

	endpoint := cfg.Okta.IDX.Issuer + "/v1/interact"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create interact http request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http call has failed: %w", err)
	}
	type interactionHandleResponse struct {
		InteractionHandle string `json:"interaction_handle"`
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("READ ERROR: %+v\n", err.Error())
	}
	defer resp.Body.Close()
	var interactionHandle interactionHandleResponse
	err = json.Unmarshal(body, &interactionHandle)
	if err != nil {
		return "", err
	}

	return interactionHandle.InteractionHandle, nil
}
