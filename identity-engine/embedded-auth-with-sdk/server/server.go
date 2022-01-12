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

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/howeyc/fsnotify"
	idx "github.com/okta/okta-idx-golang"
	"github.com/patrickmn/go-cache"

	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/config"
	"github.com/okta/samples-golang/identity-engine/embedded-auth-with-sdk/views"
)

type Server struct {
	config    *config.Config
	tpl       *template.Template
	idxClient *idx.Client
	session   *sessions.CookieStore
	view      *views.ViewConfig
	ViewData  ViewData
	cache     *cache.Cache
	svc       *http.Server
	address   string
}

type ViewData map[string]interface{}

var sessionStore = sessions.NewCookieStore([]byte("okta-direct-auth-session-store"))

func NewServer(c *config.Config) *Server {
	idx, err := idx.NewClient()
	if err != nil {
		log.Fatalf("new client error: %+v", err)
	}

	// NOTE: The cucumber testing harness Okta uses to ensure the golang samples
	// remain operational needs to be throttled so it doesn't get rate limited
	// by too many concurrent requests in tests. The idx client allows the
	// ability to set a custom http client and we make use of that feature here.
	if c.HttpClient != nil {
		idx = idx.WithHTTPClient(c.HttpClient)
	}

	return &Server{
		config:    c,
		idxClient: idx,
		session:   sessionStore,
		cache:     cache.New(5*time.Minute, 10*time.Minute),
		ViewData: map[string]interface{}{
			"Authenticated": false,
			"Errors":        "",
		},
	}
}

func (s *Server) Config() *config.Config {
	return s.config
}

func (s *Server) Session() *sessions.CookieStore {
	return sessionStore
}

func (s *Server) Address() string {
	return s.address
}

func (s *Server) Run() {
	s.parseTemplates()

	go s.watchForTemplates()

	r := mux.NewRouter()
	r.Use(s.loggingMiddleware)

	r.HandleFunc("/showView/{view}", s.showView).Methods("GET")

	r.HandleFunc("/login", s.login).Methods("GET")
	r.HandleFunc("/login", s.handleLogin).Methods("POST")
	r.HandleFunc("/login/factors", s.handleLoginSecondaryFactors).Methods("GET")
	r.HandleFunc("/login/factors/proceed", s.handleLoginSecondaryFactorsProceed).Methods("POST")
	r.HandleFunc("/login/factors/email", s.handleLoginEmailVerification).Methods("GET")
	r.HandleFunc("/login/factors/email", s.handleLoginEmailConfirmation).Methods("POST")
	r.HandleFunc("/login/factors/phone/method", s.handleLoginPhoneVerificationMethod).Methods("GET")
	r.HandleFunc("/login/factors/phone", s.handleLoginPhoneVerification).Methods("GET")
	r.HandleFunc("/login/factors/phone", s.handleLoginPhoneConfirmation).Methods("POST")
	r.HandleFunc("/login/factors/okta-verify", s.handleLoginOktaVerify).Methods("GET")
	r.HandleFunc("/login/factors/okta-verify", s.handleLoginOktaVerifyConfirmation).Methods("POST")
	r.HandleFunc("/login/factors/google_auth", s.handleLoginGoogleAuth).Methods("GET")
	r.HandleFunc("/login/factors/google_auth", s.handleLoginGoogleAuthConfirmation).Methods("POST")
	r.HandleFunc("/login/factors/google_auth/init", s.handleLoginGoogleAuthInit).Methods("GET")

	r.HandleFunc("/login/callback", s.handleLoginCallback).Methods("GET")

	r.HandleFunc("/register", s.register).Methods("GET")
	r.HandleFunc("/register", s.handleRegister).Methods("POST")
	r.HandleFunc("/enrollFactor", s.enrollFactor).Methods("GET")
	r.HandleFunc("/enrollFactor", s.handleEnrollFactor).Methods("POST")
	r.HandleFunc("/enrollEmail", s.enrollEmail).Methods("GET")
	r.HandleFunc("/enrollEmail", s.handleEnrollEmail).Methods("POST")
	r.HandleFunc("/enrollGoogleAuth", s.enrollGoogleAuth).Methods("GET")
	r.HandleFunc("/enrollGoogleAuth", s.handleEnrollGoogleAuthQRCode).Methods("POST")
	r.HandleFunc("/enrollGoogleAuth/code", s.handleEnrollGoogleAuthCode).Methods("POST")
	r.HandleFunc("/enrollOktaVerify", s.enrollOktaVerify).Methods("GET")
	r.HandleFunc("/enrollOktaVerify/qr", s.enrollOktaVerifyQR).Methods("GET")
	r.HandleFunc("/enrollOktaVerify/qr/poll", s.handleEnrollOktaVerifyQR).Methods("POST")
	r.HandleFunc("/enrollOktaVerify/sms", s.enrollOktaVerifySMS).Methods("GET")
	r.HandleFunc("/enrollOktaVerify/sms/number", s.handleEnrollOktaVerifySMSNumber).Methods("POST")
	r.HandleFunc("/enrollOktaVerify/sms/poll", s.handleEnrollOktaVerifySMS).Methods("POST")
	r.HandleFunc("/enrollOktaVerify/email", s.enrollOktaVerifyEmail).Methods("GET")
	r.HandleFunc("/enrollOktaVerify/email/address", s.handleEnrollOktaVerifyEmailAddress).Methods("POST")
	r.HandleFunc("/enrollOktaVerify/email/poll", s.handleEnrollOktaVerifyEmail).Methods("POST")
	r.HandleFunc("/enrollPhone", s.enrollPhone).Methods("GET")
	r.HandleFunc("/enrollPhone", s.enrollPhoneMethod).Methods("POST")
	r.HandleFunc("/enrollPhone/method", s.handleEnrollPhoneMethod).Methods("GET")
	r.HandleFunc("/enrollPhone/code", s.handleEnrollPhoneCode).Methods("POST")
	r.HandleFunc("/enrollPassword", s.enrollPassword).Methods("GET")
	r.HandleFunc("/enrollPassword", s.handleEnrollPassword).Methods("POST")

	r.HandleFunc("/passwordRecovery", s.passwordReset).Methods("GET")
	r.HandleFunc("/passwordRecovery", s.handlePasswordReset).Methods("POST")
	r.HandleFunc("/passwordRecovery/code", s.passwordResetCode).Methods("GET")
	r.HandleFunc("/passwordRecovery/code", s.handlePasswordResetCode).Methods("POST")
	r.HandleFunc("/passwordRecovery/newPassword", s.passwordResetNewPassword).Methods("GET")
	r.HandleFunc("/passwordRecovery/newPassword", s.handlePasswordResetNewPassword).Methods("POST")

	// General Pages
	r.HandleFunc("/", s.home)
	r.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, "direct-auth")
		if err == nil {
			s.logout(r)
			delete(session.Values, "id_token")
			delete(session.Values, "access_token")
			delete(session.Values, "Errors")
			session.Save(r, w)
		}
		s.cache.Flush()

		http.Redirect(w, r, "/", http.StatusFound)
	}).Methods("POST")
	r.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// allow GET when not logged in since it is a flow listed in the possilies on the index page
		if session, err := sessionStore.Get(r, "direct-auth"); err == nil {
			session.Values["Errors"] = "Not signed in."
			session.Save(r, w)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}).Methods("GET")
	r.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		s.ViewData["Profile"] = s.getProfileData(r)
		s.render("profile.gohtml", w, r)
	}).Methods("GET")

	addr := "127.0.0.1:8000"
	logger := log.New(os.Stderr, "http: ", log.LstdFlags)
	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		ErrorLog:     logger,
	}

	s.svc = srv
	s.address = srv.Addr

	log.Printf("running sample on addr %q\n", addr)

	if !s.config.Testing {
		log.Fatal(srv.ListenAndServe())
	} else {
		go func() {
			log.Fatal(srv.ListenAndServe())
		}()
	}
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DEBUG") == "true" || !s.Config().Testing {
			log.Printf("%s: %s\n", r.Method, r.RequestURI)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "direct-auth")
	if session.Values["Errors"] != nil {
		s.ViewData["Errors"] = session.Values["Errors"]
		delete(session.Values, "Errors")
		session.Save(r, w)
	}

	if s.IsAuthenticated(r) {
		s.ViewData["Profile"] = s.getProfileData(r)
	}
	s.render("home.gohtml", w, r)
}

func (s *Server) parseTemplates() {
	var err error
	t := template.New("")

	s.view = views.NewView(s.idxClient, sessionStore)

	s.tpl, err = t.Funcs(s.view.TemplateFuncs()).ParseGlob("views/*.gohtml")

	if err != nil {
		log.Fatalf("parse templates error: %+v", err)
	}
}

func (s *Server) watchForTemplates() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("watch templates error: %+v", err)
	}

	defer watcher.Close()

	err = watcher.Watch(viewPath(""))
	if err != nil {
		log.Fatalf("watching templates error: %+v", err)
	}

	for {
		<-watcher.Event

	wait:
		select {
		case <-watcher.Event:
			goto wait
		case <-time.After(time.Second):
		}

		log.Println("Parse Template triggered ... ")
		s.parseTemplates()
	}
}

func (s *Server) IsAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func viewPath(filename string) string {
	return path.Join("views/", filename)
}

func (s *Server) render(t string, w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "direct-auth")
	w.Header().Add("Cache-Control", "no-cache")

	s.ViewData["Authenticated"] = s.IsAuthenticated(r)

	if session.Values["Errors"] != nil {
		s.ViewData["Errors"] = session.Values["Errors"]
		delete(session.Values, "Errors")
		session.Save(r, w)
	}

	if err := s.tpl.ExecuteTemplate(w, t, s.ViewData); err != nil {
		log.Fatalf("execute templates error: %+v", err)
	}

	s.ViewData["Errors"] = ""
}

func (s *Server) getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "direct-auth")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	var reqUrl string
	issuer := s.idxClient.Config().Okta.IDX.Issuer
	if strings.Contains(issuer, "oauth2") {
		reqUrl = issuer + "/v1/userinfo"
	} else {
		reqUrl = issuer + "/oauth2/v1/userinfo"
	}

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{Timeout: time.Second * 30}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func (s *Server) showView(w http.ResponseWriter, r *http.Request) {
	view := mux.Vars(r)["view"]

	s.render(fmt.Sprintf("%s.gohtml", view), w, r)
}
