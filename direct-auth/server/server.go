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
	"context"
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
	"github.com/okta/samples-golang/direct-auth/config"
	"github.com/okta/samples-golang/direct-auth/views"
	"github.com/patrickmn/go-cache"
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
	idx, err := idx.NewClient(
		idx.WithClientID(c.Okta.IDX.ClientID),
		idx.WithClientSecret(c.Okta.IDX.ClientSecret),
		idx.WithIssuer(c.Okta.IDX.Issuer),
		idx.WithScopes(c.Okta.IDX.Scopes),
		idx.WithRedirectURI(c.Okta.IDX.RedirectURI))

	if err != nil {
		log.Fatal(err)
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

	r.HandleFunc("/login/callback", s.handleLoginCallback).Methods("GET")

	r.HandleFunc("/register", s.register).Methods("GET")
	r.HandleFunc("/register", s.handleRegister).Methods("POST")

	r.HandleFunc("/enrollFactor", s.enrollFactor).Methods("GET")
	r.HandleFunc("/enrollFactor", s.handleEnrollFactor).Methods("POST")
	r.HandleFunc("/enrollEmail", s.enrollEmail).Methods("GET")
	r.HandleFunc("/enrollEmail", s.handleEnrollEmail).Methods("POST")
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
		if err != nil {
			log.Fatalf("could not get store: %s", err)
		}
		delete(session.Values, "id_token")
		delete(session.Values, "access_token")

		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	}).Methods("POST")
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

// BEGIN: Login
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.cache.Delete("loginResponse")
	// Initialize the login so we can see if there are Social IDP's to display
	lr, err := s.idxClient.InitLogin(context.TODO())
	if err != nil {
		log.Fatalf("Could not initalize login: %s", err.Error())
	}

	// Store the login response in cache to use in the handler
	s.cache.Set("loginResponse", lr, time.Minute*5)

	// Set IDP's in the ViewData to iterate over.
	idps := lr.IdentityProviders()
	s.ViewData["IDPs"] = idps
	s.ViewData["IdpCount"] = func() int {
		return len(idps)
	}

	// Render the login page
	s.render("login.gohtml", w, r)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	s.cache.Delete("loginResponse")
	lr := clr.(*idx.LoginResponse)

	// PUll data from the web form and create your identify request
	// THis is used in the Identify step
	ir := &idx.IdentifyRequest{
		Identifier: r.FormValue("identifier"),
		Credentials: idx.Credentials{
			Password: r.FormValue("password"),
		},
	}

	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	lr, err = lr.Identify(context.TODO(), ir)
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// If we have tokens we have success, so lets store tokens
	if lr.Token() != nil {
		session.Values["access_token"] = lr.Token().AccessToken
		session.Values["id_token"] = lr.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	s.cache.Set("loginResponse", lr, time.Minute*5)
	http.Redirect(w, r, "/login/factors", http.StatusFound)
	return
}

func (s *Server) handleLoginSecondaryFactors(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)

	if lr.HasStep(idx.LoginStepEmailVerification) {
		s.ViewData["FactorEmail"] = true
	}
	if lr.HasStep(idx.LoginStepPhoneVerification) {
		s.ViewData["FactorPhone"] = true
	}
	s.render("loginSecondaryFactors.gohtml", w, r)
}

func (s *Server) handleLoginSecondaryFactorsProceed(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("push_email") != "" {
		http.Redirect(w, r, "/login/factors/email", http.StatusFound)
		return
	}
	if r.FormValue("push_phone") != "" {
		http.Redirect(w, r, "/login/factors/phone/method", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login/factors", http.StatusFound)
}

func (s *Server) handleLoginEmailVerification(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)
	if !lr.HasStep(idx.LoginStepEmailVerification) {
		http.Redirect(w, r, "/login/factors", http.StatusFound)
		return
	}
	invCode, ok := s.ViewData["InvalidEmailCode"]
	if !ok || !invCode.(bool) {
		lr, err := lr.VerifyEmail(r.Context())
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		s.cache.Set("loginResponse", lr, time.Minute*5)
	}
	s.render("loginFactorEmail.gohtml", w, r)
}

func (s *Server) handleLoginEmailConfirmation(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)
	if !lr.HasStep(idx.LoginStepEmailConfirmation) {
		http.Redirect(w, r, "login/", http.StatusFound)
		return
	}
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	lr, err = lr.ConfirmEmail(r.Context(), r.FormValue("code"))
	if err != nil {
		s.ViewData["InvalidEmailCode"] = true
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login/factors/email", http.StatusFound)
		return
	}
	s.cache.Set("loginResponse", lr, time.Minute*5)
	s.ViewData["InvalidEmailCode"] = false

	// If we have tokens we have success, so lets store tokens
	if lr.Token() != nil {
		session, err := sessionStore.Get(r, "direct-auth")
		if err != nil {
			log.Fatalf("could not get store: %s", err)
		}
		session.Values["access_token"] = lr.Token().AccessToken
		session.Values["id_token"] = lr.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
		// redirect the user to /profile
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	lr, err = lr.WhereAmI(r.Context())
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.cache.Set("loginResponse", lr, time.Minute*5)
	http.Redirect(w, r, "/login/factors", http.StatusFound)
}

func (s *Server) handleLoginPhoneVerificationMethod(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)
	if !lr.HasStep(idx.LoginStepPhoneVerification) {
		http.Redirect(w, r, "/login/factors", http.StatusFound)
		return
	}
	s.render("loginFactorPhoneMethod.gohtml", w, r)
}

func (s *Server) handleLoginPhoneVerification(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)
	if !lr.HasStep(idx.LoginStepPhoneVerification) {
		http.Redirect(w, r, "/login/factors", http.StatusFound)
		return
	}
	// get method
	a := r.FormValue("voice")
	b := r.FormValue("sms")
	_ = a
	_ = b
	invCode, ok := s.ViewData["InvalidPhoneCode"]
	if !ok || !invCode.(bool) {
		lr, err := lr.VerifyPhone(r.Context(), idx.PhoneMethodSMS)
		if err != nil {
			http.Redirect(w, r, "/login/factors", http.StatusFound)
			return
		}
		s.cache.Set("loginResponse", lr, time.Minute*5)
	}
	s.render("loginFactorPhone.gohtml", w, r)
}

func (s *Server) handleLoginPhoneConfirmation(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)
	if !lr.HasStep(idx.LoginStepPhoneConfirmation) {
		http.Redirect(w, r, "/login/factors", http.StatusFound)
		return
	}
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	lr, err = lr.ConfirmPhone(r.Context(), r.FormValue("code"))
	if err != nil {
		s.ViewData["InvalidPhoneCode"] = true
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login/factors/phone", http.StatusFound)
		return
	}
	s.ViewData["InvalidPhoneCode"] = false
	// If we have tokens we have success, so lets store tokens
	if lr.Token() != nil {
		session, err := sessionStore.Get(r, "direct-auth")
		if err != nil {
			log.Fatalf("could not get store: %s", err)
		}
		session.Values["access_token"] = lr.Token().AccessToken
		session.Values["id_token"] = lr.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
		// redirect the user to /profile
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	lr, err = lr.WhereAmI(r.Context())
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.cache.Set("loginResponse", lr, time.Minute*5)
	http.Redirect(w, r, "/login/factors", http.StatusFound)
}

func (s *Server) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	s.cache.Delete("loginResponse")
	lr := clr.(*idx.LoginResponse)

	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	lr, err = lr.WhereAmI(context.TODO())
	if err != nil {
		log.Fatalf("could not tell where I am: %s", err)
	}

	if !lr.HasStep(idx.LoginStepSuccess) {
		var steps []string
		for _, step := range lr.AvailableSteps() {
			steps = append(steps, step.String())
		}
		fmt.Printf("Non Success after IDP Redirect not supported. Available steps: %s", strings.Join(steps, ","))
		session.Values["Errors"] = "Multifactor Authentication and Social Identity Providers is not currently supported, Authentication failed."
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// If we have tokens we have success, so lets store tokens
	if lr.Token() != nil {
		session.Values["access_token"] = lr.Token().AccessToken
		session.Values["id_token"] = lr.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
	} else {
		session.Values["Errors"] = "We expected tokens to be available here but were not. Authentication Failed."
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// redirect the user to /profile
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	s.render("register.gohtml", w, r)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	profile := &idx.UserProfile{
		FirstName: r.FormValue("firstName"),
		LastName:  r.FormValue("lastName"),
		Email:     r.FormValue("email"),
	}

	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	enrollResponse, err := s.idxClient.InitProfileEnroll(context.TODO(), profile)
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	if enrollResponse.HasStep(idx.EnrollmentStepPasswordSetup) {
		http.Redirect(w, r, "/enrollPassword", http.StatusFound)
		return
	}
}

func (s *Server) enrollFactor(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if enrollResponse.HasStep(idx.EnrollmentStepSkip) {
		s.ViewData["skip"] = true
	} else {
		s.ViewData["skip"] = false
	}
	if enrollResponse.HasStep(idx.EnrollmentStepPhoneVerification) {
		s.ViewData["FactorPhone"] = true
	} else {
		s.ViewData["FactorPhone"] = false
	}
	if enrollResponse.HasStep(idx.EnrollmentStepEmailVerification) {
		s.ViewData["FactorEmail"] = true
	} else {
		s.ViewData["FactorEmail"] = false
	}
	s.render("enroll.gohtml", w, r)
}

func (s *Server) handleEnrollFactor(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("push_email") != "" {
		http.Redirect(w, r, "/enrollEmail", http.StatusFound)
		return
	}
	if r.FormValue("push_phone") != "" {
		http.Redirect(w, r, "/enrollPhone", http.StatusFound)
		return
	}
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	if enrollResponse.HasStep(idx.EnrollmentStepSkip) {
		enrollResponse, err = enrollResponse.Skip(r.Context())
		if err != nil {
			session.Values["Errors"] = err.Error()
			session.Save(r, w)
			http.Redirect(w, r, "/register", http.StatusFound)
			return
		}
		// If we have tokens we have success, so lets store tokens
		if enrollResponse.Token() != nil {
			session, err := sessionStore.Get(r, "direct-auth")
			if err != nil {
				log.Fatalf("could not get store: %s", err)
			}
			session.Values["access_token"] = enrollResponse.Token().AccessToken
			session.Values["id_token"] = enrollResponse.Token().IDToken
			err = session.Save(r, w)
			if err != nil {
				log.Fatalf("could not save access token: %s", err)
			}
			// redirect the user to /profile
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		enrollResponse, err = enrollResponse.WhereAmI(r.Context())
		if err != nil {
			session.Values["Errors"] = err.Error()
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)

	}
	http.Redirect(w, r, "/enrollFactor", http.StatusFound)
}

func (s *Server) enrollPassword(w http.ResponseWriter, r *http.Request) {
	s.render("enrollPassword.gohtml", w, r)
}

func (s *Server) handleEnrollPassword(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)

	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	if newPassword != confirmPassword {
		session.Values["Errors"] = "Passwords do not match"
		session.Save(r, w)
		http.Redirect(w, r, "/enrollPassword", http.StatusFound)
		return
	}

	enrollResponse, err = enrollResponse.SetNewPassword(context.TODO(), r.FormValue("newPassword"))
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/enrollPassword", http.StatusFound)
		return
	}

	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	if !enrollResponse.HasStep(idx.EnrollmentStepSuccess) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	if enrollResponse.Token() != nil {
		session.Values["access_token"] = enrollResponse.Token().AccessToken
		session.Values["id_token"] = enrollResponse.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
	} else {
		session.Values["Errors"] = "This sample does not support this use case, please review your policy setup and try again."
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) enrollPhone(w http.ResponseWriter, r *http.Request) {
	s.render("enrollPhone.gohtml", w, r)
}

func (s *Server) enrollPhoneMethod(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	session.Values["phoneNumber"] = r.FormValue("phoneNumber")
	session.Save(r, w)
	s.render("enrollPhoneMethod.gohtml", w, r)
}

func (s *Server) handleEnrollPhoneCode(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)

	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	enrollResponse, err = enrollResponse.ConfirmPhone(r.Context(), r.FormValue("code"))
	if err != nil {
		s.ViewData["InvalidPhoneCode"] = true
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		s.render("enrollPhoneCode.gohtml", w, r)
		return
	}
	s.ViewData["InvalidPhoneCode"] = false
	// If we have tokens we have success, so lets store tokens
	if enrollResponse.Token() != nil {
		session, err := sessionStore.Get(r, "direct-auth")
		if err != nil {
			log.Fatalf("could not get store: %s", err)
		}
		session.Values["access_token"] = enrollResponse.Token().AccessToken
		session.Values["id_token"] = enrollResponse.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
		// redirect the user to /profile
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse, err = enrollResponse.WhereAmI(r.Context())
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	http.Redirect(w, r, "/enrollFactor", http.StatusFound)
}

func (s *Server) handleEnrollPhoneMethod(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	pn := session.Values["phoneNumber"]
	if pn == nil {
		session.Values["Errors"] = "Invalid phone phone Number"
		session.Save(r, w)
		http.Redirect(w, r, "/enrollPhone", http.StatusFound)
		return
	}
	var pm idx.PhoneOption
	spm := session.Values["phoneMethod"]
	if spm != nil {
		pm = spm.(idx.PhoneOption)
	} else if r.FormValue("voice") != "" {
		pm = idx.PhoneMethodVoiceCall
	} else if r.FormValue("sms") != "" {
		pm = idx.PhoneMethodSMS
	} else {
		session.Values["Errors"] = "Unsupported phone method"
		session.Save(r, w)
		http.Redirect(w, r, "/enrollPhone/method", http.StatusFound)
		return
	}
	session.Values["phoneMethod"] = pm
	session.Save(r, w)

	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)

	invCode, ok := s.ViewData["InvalidPhoneCode"]
	if !ok || !invCode.(bool) {
		enrollResponse, err = enrollResponse.VerifyPhone(r.Context(), pm, pn.(string))
		if err != nil {
			session.Values["Errors"] = err.Error()
			session.Save(r, w)
			http.Redirect(w, r, "/enrollFactor", http.StatusFound)
			return
		}
		s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	}
	s.render("enrollPhoneCode.gohtml", w, r)
}

func (s *Server) enrollEmail(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepEmailVerification) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	invCode, ok := s.ViewData["InvalidEmailCode"]
	if !ok || !invCode.(bool) {
		enrollResponse, err := enrollResponse.VerifyEmail(r.Context())
		if err != nil {
			http.Redirect(w, r, "/enrollFactor", http.StatusFound)
			return
		}
		s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	}
	s.render("enrollEmail.gohtml", w, r)
}

func (s *Server) handleEnrollEmail(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepEmailConfirmation) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	enrollResponse, err = enrollResponse.ConfirmEmail(r.Context(), r.FormValue("code"))
	if err != nil {
		s.ViewData["InvalidEmailCode"] = true
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/enrollEmail", http.StatusFound)
		return
	}
	s.ViewData["InvalidEmailCode"] = false
	if enrollResponse.Token() != nil {
		session, err := sessionStore.Get(r, "direct-auth")
		if err != nil {
			log.Fatalf("could not get store: %s", err)
		}
		session.Values["access_token"] = enrollResponse.Token().AccessToken
		session.Values["id_token"] = enrollResponse.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
		// redirect the user to /profile
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse, err = enrollResponse.WhereAmI(r.Context())
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	http.Redirect(w, r, "/enrollFactor", http.StatusFound)
}

func (s *Server) passwordReset(w http.ResponseWriter, r *http.Request) {
	s.render("resetPassword.gohtml", w, r)
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	ir := &idx.IdentifyRequest{
		Identifier: r.FormValue("identifier"),
	}

	rpr, err := s.idxClient.InitPasswordReset(context.TODO(), ir)
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	// At this point, we expect to be able to send an email
	// for a password reset, so we need to accept the code
	// that was sent to the email address. If step does
	// not exist, we encountered an error.
	if !rpr.HasStep(idx.ResetPasswordStepEmailVerification) {
		session.Values["Errors"] = "We encountered an unexpected error, please try again"
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	rpr, err = rpr.VerifyEmail(context.TODO())
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	if !rpr.HasStep(idx.ResetPasswordStepEmailConfirmation) {
		session.Values["Errors"] = "We encountered an unexpected error, please try again"
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	s.cache.Set("resetPasswordFlow", rpr, time.Minute*5)

	http.Redirect(w, r, "/passwordRecovery/code", http.StatusFound)
	return
}

func (s *Server) passwordResetCode(w http.ResponseWriter, r *http.Request) {
	s.render("resetPasswordCode.gohtml", w, r)
}

func (s *Server) handlePasswordResetCode(w http.ResponseWriter, r *http.Request) {
	tmp, _ := s.cache.Get("resetPasswordFlow")
	rpr := tmp.(*idx.ResetPasswordResponse)

	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	rpr, err = rpr.ConfirmEmail(context.TODO(), r.FormValue("code"))
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery/code", http.StatusFound)
		return
	}

	if !rpr.HasStep(idx.ResetPasswordStepNewPassword) {
		rpr.Cancel(context.TODO())
		session.Values["Errors"] = "We encountered an unexpected error, please try again"
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	s.cache.Set("resetPasswordFlow", rpr, time.Minute*5)

	http.Redirect(w, r, "/passwordRecovery/newPassword", http.StatusFound)
	return
}

func (s *Server) passwordResetNewPassword(w http.ResponseWriter, r *http.Request) {
	s.render("resetPasswordNewPassword.gohtml", w, r)
}

func (s *Server) handlePasswordResetNewPassword(w http.ResponseWriter, r *http.Request) {
	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	if newPassword != confirmPassword {
		session.Values["Errors"] = "Passwords do not match"
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery/newPassword", http.StatusFound)
		return
	}

	tmp, _ := s.cache.Get("resetPasswordFlow")
	rpr := tmp.(*idx.ResetPasswordResponse)

	rpr, err = rpr.SetNewPassword(context.TODO(), newPassword)
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery/newPassword", http.StatusFound)
		return
	}

	if !rpr.HasStep(idx.ResetPasswordStepSuccess) {
		rpr.Cancel(context.TODO())
		session.Values["Errors"] = "This sample does not support this use case, please review your policy setup and try again."
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	// If we have tokens we have success, so lets store tokens
	if rpr.Token() != nil {
		session.Values["access_token"] = rpr.Token().AccessToken
		session.Values["id_token"] = rpr.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
	} else {
		session.Values["Errors"] = "This sample does not support this use case, please review your policy setup and try again."
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}

	// redirect the user to /profile
	http.Redirect(w, r, "/", http.StatusFound)
	return
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if s.IsAuthenticated(r) {
		s.ViewData["Profile"] = s.getProfileData(r)
	}
	s.render("home.gohtml", w, r)
}

func (s *Server) parseTemplates() {
	var err error
	t := template.New("")

	s.view = views.NewView(s.config, sessionStore)

	s.tpl, err = t.Funcs(s.view.TemplateFuncs()).ParseGlob("views/*")

	if err != nil {
		log.Fatal(err)
	}
}

func (s *Server) watchForTemplates() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	defer watcher.Close()

	err = watcher.Watch(viewPath(""))
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	s.ViewData["Errors"] = ""
}

func (s *Server) getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "direct-auth")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := s.config.Okta.IDX.Issuer + "/v1/userinfo"

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

func (s *Server) showView(w http.ResponseWriter, r *http.Request) {
	view := mux.Vars(r)["view"]

	s.render(fmt.Sprintf("%s.gohtml", view), w, r)
}
