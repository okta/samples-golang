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
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	idx "github.com/okta/okta-idx-golang"

	"github.com/okta/samples-golang/identity-engine/embedded-sign-in-widget/config"
)

const (
	SESSION_STORE_NAME = "okta-self-hosted-session-store"
)

type Server struct {
	config            *config.Config
	idxClient         *idx.Client
	currentIdxContext *idx.Context
	tpl               *template.Template
	sessionStore      *sessions.CookieStore
	LoginData         LoginData
	svc               *http.Server
	address           string
}

type LoginData struct {
	IsAuthenticated     bool
	BaseUrl             string
	ClientId            string
	RedirectURI         string
	Issuer              string
	State               string
	InteractionHandle   string
	CodeChallenge       string
	CodeChallengeMethod string
}

func NewServer(c *config.Config) *Server {
	idx, err := idx.NewClient()
	if err != nil {
		log.Fatalf("new client error: %+v", err)
	}

	return &Server{
		config:       c,
		tpl:          template.Must(template.ParseGlob("templates/*.gohtml")),
		idxClient:    idx,
		sessionStore: sessions.NewCookieStore([]byte("randomKey")),
	}
}

func (s *Server) Address() string {
	return s.address
}

func (s *Server) Run() {
	r := mux.NewRouter()
	r.Use(s.loggingMiddleware)

	r.HandleFunc("/", s.HomeHandler).Methods("GET")

	r.HandleFunc("/login", s.LoginHandler).Methods("GET")
	r.HandleFunc("/login/callback", s.LoginCallbackHandler).Methods("GET")
	r.HandleFunc("/profile", s.ProfileHandler).Methods("GET")
	r.HandleFunc("/logout", s.LogoutHandler).Methods("POST")
	r.HandleFunc("/logout", s.LogoutHandler).Methods("GET")

	addr := "localhost:8000"
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

func (s *Server) HomeHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}

	s.tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	lr, err := s.idxClient.InitLogin(r.Context())
	if err != nil {
		log.Fatalf("error idx client init login: %+v", err)
	}

	if s.currentIdxContext == nil {
		idxContext, err := s.idxClient.Interact(r.Context())
		if err != nil {
			log.Fatalf("error idx context: %+v", err)
		}
		s.currentIdxContext = idxContext
	}

	issuerURL := s.idxClient.Config().Okta.IDX.Issuer
	issuerParts, err := url.Parse(issuerURL)
	if err != nil {
		log.Fatalf("error: %s\n", err.Error())
	}
	baseUrl := issuerParts.Scheme + "://" + issuerParts.Hostname()
	s.LoginData = LoginData{
		IsAuthenticated:     lr.IsAuthenticated(),
		BaseUrl:             baseUrl,
		RedirectURI:         s.idxClient.Config().Okta.IDX.RedirectURI,
		ClientId:            s.idxClient.Config().Okta.IDX.ClientID,
		Issuer:              s.idxClient.Config().Okta.IDX.Issuer,
		State:               s.currentIdxContext.State,
		CodeChallenge:       s.currentIdxContext.CodeChallenge,
		CodeChallengeMethod: s.currentIdxContext.CodeChallengeMethod,
		InteractionHandle:   s.currentIdxContext.InteractionHandle.InteractionHandle,
	}
	err = s.tpl.ExecuteTemplate(w, "login.gohtml", s.LoginData)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
	}
}

func (s *Server) LoginCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check if interaction_required error is returned
	if r.URL.Query().Get("error") == "interaction_required" {
		w.Header().Add("Cache-Control", "no-cache")

		s.LoginData.IsAuthenticated = s.isAuthenticated(r)
		err := s.tpl.ExecuteTemplate(w, "login.gohtml", s.LoginData)
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
		return
	}

	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != s.currentIdxContext.State {
		fmt.Fprintf(w, "The state was not as expected, got %q, expected %q", r.URL.Query().Get("state"), s.currentIdxContext.State)
		return
	}

	// Check that the interaction_code was provided
	if r.URL.Query().Get("interaction_code") == "" {
		fmt.Fprintln(w, "The interaction_code was not returned or is not accessible")
		return
	}

	session, err := s.sessionStore.Get(r, SESSION_STORE_NAME)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	accessToken, err := s.idxClient.RedeemInteractionCode(r.Context(), s.currentIdxContext, r.URL.Query().Get("interaction_code"))
	if err != nil {
		log.Fatalf("access token error: %+v\n", err)
	}
	session.Values["id_token"] = accessToken.IDToken
	session.Values["access_token"] = accessToken.AccessToken
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Profile         map[string]string
		IsAuthenticated bool
	}{
		Profile:         s.getProfileData(r),
		IsAuthenticated: s.isAuthenticated(r),
	}
	s.tpl.ExecuteTemplate(w, "profile.gohtml", data)
}

func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// revoke the oauth2 access token it exists in the session API side before deleting session info
	logoutURL := "/"
	if session, err := s.sessionStore.Get(r, SESSION_STORE_NAME); err == nil {
		if accessToken, found := session.Values["access_token"]; found {
			if err := s.idxClient.RevokeToken(r.Context(), accessToken.(string)); err != nil {
				fmt.Printf("revoke error: %+v\n", err)
			}
		}

		if idToken, found := session.Values["id_token"]; found {
			// redirect must match one of the "Sign-out redirect URIs" defined on the Okta application
			redirect, _ := url.Parse(s.idxClient.Config().Okta.IDX.RedirectURI)
			redirect.Path = "/"
			params := url.Values{
				"id_token_hint":            {idToken.(string)},
				"post_logout_redirect_uri": {redirect.String()},
			}
			// server must redirect out to the Okta API to perform a proper logout
			logoutURL = s.oAuthEndPoint(fmt.Sprintf("logout?%s", params.Encode()))
		}

		delete(session.Values, "id_token")
		delete(session.Values, "access_token")
		session.Save(r, w)
	}

	// reset the idx context
	s.currentIdxContext = nil
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DEBUG") == "true" || !s.config.Testing {
			log.Printf("%s: %s\n", r.Method, r.RequestURI)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, _ := s.sessionStore.Get(r, SESSION_STORE_NAME)
	if accessToken, found := session.Values["access_token"]; found {
		reqUrl := s.oAuthEndPoint("userinfo")
		req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
		h := req.Header
		h.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		h.Add("Accept", "application/json")

		client := &http.Client{Timeout: time.Second * 30}
		resp, _ := client.Do(req)
		body, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		json.Unmarshal(body, &m)
	}

	return m
}

func (s *Server) isAuthenticated(r *http.Request) bool {
	session, _ := s.sessionStore.Get(r, SESSION_STORE_NAME)
	_, found := session.Values["id_token"]
	return found
}

func (s *Server) oAuthEndPoint(operation string) string {
	var endPoint string
	issuer := s.idxClient.Config().Okta.IDX.Issuer
	if strings.Contains(issuer, "oauth2") {
		endPoint = fmt.Sprintf("%s/v1/%s", issuer, operation)
	} else {
		endPoint = fmt.Sprintf("%s/oauth2/v1/%s", issuer, operation)
	}
	return endPoint
}
