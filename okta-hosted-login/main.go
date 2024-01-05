package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	oktaUtils.ParseEnvironment()

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/authorization-code/callback", AuthCodeCallbackHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)

	log.Print("server starting at localhost:8080 ... ")
	err := http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
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

	// Create a session and generate a new nonce for each login attempt
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, _ := oktaUtils.GenerateNonce()
	session.Values["nonce"] = nonce // Store the nonce in the session
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != state {
		fmt.Fprintln(w, "The state was not as expected")
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Fprintln(w, "The code was not returned or is not accessible")
		return
	}

	exchange := exchangeCode(r.URL.Query().Get("code"), r)
	if exchange.Error != "" {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		return
	}

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the nonce from the session
	sessionNonce, ok := session.Values["nonce"].(string)
	if !ok || sessionNonce == "" {
		fmt.Fprintln(w, "Nonce could not be retrieved from the session.")
		return
	}

	_, verificationError := verifyToken(exchange.IdToken, sessionNonce)

	if verificationError != nil {
		fmt.Println(verificationError)
	}

	if verificationError == nil {
		session.Values["id_token"] = exchange.IdToken
		session.Values["access_token"] = exchange.AccessToken

		session.Save(r, w)
	}

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

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) Exchange {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

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

func verifyToken(t string, nonce string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce // Use the nonce from the session
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
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
