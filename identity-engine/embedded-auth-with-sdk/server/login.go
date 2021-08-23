package server

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	idx "github.com/okta/okta-idx-golang"
)

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

// logout revokes the oauth2 token server side
func (s *Server) logout(r *http.Request) {
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return
	}

	var revokeTokenUrl string
	issuer := s.idxClient.Config().Okta.IDX.Issuer
	if strings.Contains(issuer, "oauth2") {
		revokeTokenUrl = issuer + "/v1/revoke"
	} else {
		revokeTokenUrl = issuer + "/oauth2/v1/revoke"
	}

	form := url.Values{}
	form.Set("token", session.Values["access_token"].(string))
	form.Set("token_type_hint", "access_token")
	form.Set("client_id", s.idxClient.Config().Okta.IDX.ClientID)
	form.Set("client_secret", s.idxClient.Config().Okta.IDX.ClientSecret)
	req, _ := http.NewRequest("POST", revokeTokenUrl, strings.NewReader(form.Encode()))
	h := req.Header
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: time.Second * 30}
	resp, err := client.Do(req)
	if err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("revoke error; status: %s, body: %s\n", resp.Status, string(body))
	}
	defer resp.Body.Close()
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
	} else {
		s.ViewData["FactorEmail"] = false
	}
	if lr.HasStep(idx.LoginStepPhoneVerification) || lr.HasStep(idx.LoginStepPhoneInitialVerification) {
		s.ViewData["FactorPhone"] = true
	} else {
		s.ViewData["FactorPhone"] = false
	}
	s.render("loginSecondaryFactors.gohtml", w, r)
}

func (s *Server) handleLoginSecondaryFactorsProceed(w http.ResponseWriter, r *http.Request) {
	delete(s.ViewData, "InvalidEmailCode")
	pushFactor := r.FormValue("push_factor")
	if pushFactor == "push_email" {
		http.Redirect(w, r, "/login/factors/email", http.StatusFound)
		return
	}
	if pushFactor == "push_phone" {
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
	if lr.HasStep(idx.LoginStepPhoneInitialVerification) || lr.HasStep(idx.LoginStepPhoneVerification) {
		if lr.HasStep(idx.LoginStepPhoneInitialVerification) {
			s.ViewData["InitialPhoneSetup"] = true
		} else {
			s.ViewData["InitialPhoneSetup"] = false
		}
		s.render("loginFactorPhoneMethod.gohtml", w, r)
		return
	}
	http.Redirect(w, r, "/login/factors", http.StatusFound)
}

func (s *Server) handleLoginPhoneVerification(w http.ResponseWriter, r *http.Request) {
	clr, _ := s.cache.Get("loginResponse")
	lr := clr.(*idx.LoginResponse)
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	if lr.HasStep(idx.LoginStepPhoneInitialVerification) || lr.HasStep(idx.LoginStepPhoneVerification) {
		// get method
		_ = r.FormValue("voice")
		_ = r.FormValue("sms")
		invCode, ok := s.ViewData["InvalidPhoneCode"]
		if !ok || !invCode.(bool) {
			var err error
			if lr.HasStep(idx.LoginStepPhoneInitialVerification) {
				lr, err = lr.VerifyPhoneInitial(r.Context(), idx.PhoneMethodSMS, r.FormValue("phoneNumber"))
			} else {
				lr, err = lr.VerifyPhone(r.Context(), idx.PhoneMethodSMS)
			}
			if err != nil {
				session.Values["Errors"] = err.Error()
				session.Save(r, w)
				http.Redirect(w, r, "/login/factors/phone/method", http.StatusFound)
				return
			}
			s.cache.Set("loginResponse", lr, time.Minute*5)
		}
		s.render("loginFactorPhone.gohtml", w, r)
		return
	}
	http.Redirect(w, r, "/login/factors", http.StatusFound)
	return
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
