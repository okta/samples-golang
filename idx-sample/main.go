package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	idx "github.com/okta/okta-idx-golang"
	"github.com/patrickmn/go-cache"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	client       *idx.Client
	memCache     *cache.Cache
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func main() {
	var err error
	client, err = idx.NewClient(
		idx.WithClientID(os.Getenv("CLIENT_ID")),
		idx.WithClientSecret(os.Getenv("CLIENT_SECRET")),
		idx.WithIssuer(os.Getenv("ISSUER")),
		idx.WithScopes([]string{"openid", "profile"}),
		idx.WithRedirectURI("https://okta.com"),
	)
	if err != nil {
		panic(err)
	}
	memCache = cache.New(5*time.Minute, 10*time.Minute)
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)

	http.HandleFunc("/password/reset", PasswordResetInitialHandler)
	http.HandleFunc("/password/reset/name", PasswordResetIDHandler)
	http.HandleFunc("/password/reset/email", PasswordResetEmailHandler)
	http.HandleFunc("/password/reset/passcode", PasswordResetPasscodeHandler)

	http.HandleFunc("/account/new", NewAccountInitialHandler)
	http.HandleFunc("/account/new/name", NewAccountIDHandler)
	http.HandleFunc("/account/new/email", NewAccountEmailHandler)
	http.HandleFunc("/account/new/passcode", NewAccountPasscodeHandler)

	log.Print("server starting at localhost:8080 ... ")
	err = http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

type customData struct {
	Profile         map[string]string
	IsAuthenticated bool
	IsResetPassword bool

	IsInitialResetPassword bool
	IsWaitingForEmail      bool
	IsNewPassword          bool

	IsInitialAccountCreate bool
	IsNewAccount           bool
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
	}
	tpl.ExecuteTemplate(w, "profile.gohtml", data)
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
	resp, err := client.Do(req)
	_ = err
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)
	return m
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}
