package server

import (
	"context"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	idx "github.com/okta/okta-idx-golang"
)

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

	if errors, ok := s.cache.Get("Errors"); ok {
		s.ViewData["Errors"] = errors
		s.cache.Delete("Errors")
	}

	if enrollResponse.EnrollmentSuccess() {
		s.transitionToProfile(enrollResponse, w, r)
		return
	}

	s.ViewData["FactorSkip"] = enrollResponse.HasStep(idx.EnrollmentStepSkip)
	s.ViewData["FactorPhone"] = enrollResponse.HasStep(idx.EnrollmentStepPhoneVerification)
	s.ViewData["FactorEmail"] = enrollResponse.HasStep(idx.EnrollmentStepEmailVerification)
	s.ViewData["FactorOktaVerify"] = enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit)
	s.ViewData["FactorGoogleAuth"] = enrollResponse.HasStep(idx.EnrollmentStepGoogleAuthenticatorInit)
	s.ViewData["FactorWebAuthN"] = enrollResponse.HasStep(idx.EnrollmentStepWebAuthNSetup)
	s.ViewData["FactorSecurityQuestion"] = enrollResponse.HasStep(idx.EnrollmentStepSecurityQuestionOptions)

	if !enrollResponse.HasStep(idx.EnrollmentStepPhoneVerification) &&
		!enrollResponse.HasStep(idx.EnrollmentStepEmailVerification) &&
		!enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) &&
		!enrollResponse.HasStep(idx.EnrollmentStepGoogleAuthenticatorInit) &&
		!enrollResponse.HasStep(idx.EnrollmentStepWebAuthNSetup) &&
		!enrollResponse.HasStep(idx.EnrollmentStepSecurityQuestionOptions) {
		s.transitionToProfile(enrollResponse, w, r)
		return
	}

	s.render("enroll.gohtml", w, r)
}

func (s *Server) handleEnrollFactor(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)

	submit := r.FormValue("submit")
	if submit == "Skip" {
		s.transitionToProfile(enrollResponse, w, r)
		return
	}

	pushFactor := r.FormValue("push_factor")
	switch pushFactor {
	case "push_email":
		http.Redirect(w, r, "/enrollEmail", http.StatusFound)
		return
	case "push_phone":
		http.Redirect(w, r, "/enrollPhone", http.StatusFound)
		return
	case "push_okta_verify":
		http.Redirect(w, r, "/enrollOktaVerify", http.StatusFound)
		return
	case "push_google_auth":
		http.Redirect(w, r, "/enrollGoogleAuth", http.StatusFound)
		return
	case "push_web_authn":
		http.Redirect(w, r, "/enrollWebAuthN", http.StatusFound)
		return
	case "push_security_question":
		http.Redirect(w, r, "/enrollSecurityQuestion", http.StatusFound)
		return
	}
	if enrollResponse.HasStep(idx.EnrollmentStepSkip) {
		s.transitionToProfile(enrollResponse, w, r)
	}
	http.Redirect(w, r, "/enrollFactor", http.StatusFound)
}

func (s *Server) transitionToProfile(er *idx.EnrollmentResponse, w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	// skip can be an option if we aren't at the conclusion of enrollment success
	if !er.EnrollmentSuccess() {
		er, err := er.Skip(r.Context())
		if err != nil {
			session.Values["Errors"] = err.Error()
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		s.cache.Set("enrollResponse", er, time.Minute*5)
	}

	if er.Token() != nil {
		session.Values["access_token"] = er.Token().AccessToken
		session.Values["id_token"] = er.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
	} else {
		log.Fatal("attempting to transition to profile but no token is present")
	}

	http.Redirect(w, r, "/", http.StatusFound)
	return
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
	s.cache.Set("phoneNumber", r.FormValue("phoneNumber"), time.Minute*5)
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
	pn, _ := s.cache.Get("phoneNumber")
	if pn == nil {
		session.Values["Errors"] = "Invalid phone phone Number"
		session.Save(r, w)
		http.Redirect(w, r, "/enrollPhone", http.StatusFound)
		return
	}
	var pm idx.PhoneOption
	spm, _ := s.cache.Get("phoneMethod")
	if spm != nil {
		pm = spm.(idx.PhoneOption)
	} else if r.FormValue("mobile_factor") == "voice" {
		pm = idx.PhoneMethodVoiceCall
	} else if r.FormValue("mobile_factor") == "sms" {
		pm = idx.PhoneMethodSMS
	} else {
		session.Values["Errors"] = "Unsupported phone method"
		session.Save(r, w)
		http.Redirect(w, r, "/enrollPhone/method", http.StatusFound)
		return
	}
	s.cache.Set("phoneMethod", pm, time.Minute*6)

	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)

	invCode, ok := s.ViewData["InvalidPhoneCode"]
	if !ok || !invCode.(bool) {
		enrollResponse, err = enrollResponse.VerifyPhone(r.Context(), pm, pn.(string))
		if err != nil {
			s.cache.Set("Errors", err.Error(), time.Minute*5)
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

func (s *Server) enrollOktaVerify(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) {
		s.ViewData["Errors"] = "Missing enrollment step Okta Verify"
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	s.render("enrollOktaVerify.gohtml", w, r)
}

func (s *Server) enrollOktaVerifyQR(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) {
		s.ViewData["Errors"] = "Missing enrollment step Okta Verify"
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	enrollResponse, err := enrollResponse.OktaVerifyInit(r.Context(), idx.OktaVerifyOptionQRCode)
	if err != nil {
		log.Fatalf("okta verify error: %s", err)
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	s.ViewData["QRCode"] = enrollResponse.ContextualData().QRcode.Href
	s.render("enrollOktaVerifyQR.gohtml", w, r)
}

func (s *Server) handleEnrollOktaVerifyQR(w http.ResponseWriter, r *http.Request) {
	// we don't need to poll anylonger if enrollment step enroll poll is missing  and enroll okta verify is missing
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	_, continuePolling, err := enrollResponse.OktaVerifyContinuePolling(r.Context())
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	if err != nil {
		log.Fatalf("okta verify confirmation error: %s", err)
	}

	data := struct {
		ContinuePolling bool
		Next            string
	}{continuePolling, "/enrollFactor"}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(resp)
}

func (s *Server) enrollOktaVerifySMS(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) {
		s.ViewData["Errors"] = "Missing enrollment step Okta Verify"
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	s.render("enrollOktaVerifySMS.gohtml", w, r)
}

func (s *Server) handleEnrollOktaVerifySMSNumber(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) {
		s.ViewData["Errors"] = "Missing enrollment step Okta Verify"
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	var data map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		panic(err)
	}
	phoneNumber, found := data["phoneNumber"]
	if !found {
		panic(data)
	}

	enrollResponse, err = enrollResponse.OktaVerifySMSInit(r.Context(), phoneNumber.(string))
	if err != nil {
		log.Fatalf("okta verify error: %s", err)
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEnrollOktaVerifySMS(w http.ResponseWriter, r *http.Request) {
	// we don't need to poll anylonger if enrollment step enroll poll is missing  and enroll okta verify is missing
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	_, continuePolling, err := enrollResponse.OktaVerifyContinuePolling(r.Context())
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	if err != nil {
		log.Fatalf("okta verify confirmation error: %s", err)
	}

	data := struct {
		ContinuePolling bool
		Next            string
	}{continuePolling, "/enrollFactor"}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(resp)
}

func (s *Server) enrollOktaVerifyEmail(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) {
		s.ViewData["Errors"] = "Missing enrollment step Okta Verify"
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	s.render("enrollOktaVerifyEmail.gohtml", w, r)
}

func (s *Server) handleEnrollOktaVerifyEmailAddress(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepOktaVerifyInit) {
		s.ViewData["Errors"] = "Missing enrollment step Okta Verify"
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	var data map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		panic(err)
	}
	email, found := data["email"]
	if !found {
		panic(data)
	}

	enrollResponse, err = enrollResponse.OktaVerifyEmailInit(r.Context(), email.(string))
	if err != nil {
		log.Fatalf("okta verify error: %s", err)
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEnrollOktaVerifyEmail(w http.ResponseWriter, r *http.Request) {
	// we don't need to poll anylonger if enrollment step enroll poll is missing  and enroll okta verify is missing
	cer, _ := s.cache.Get("enrollResponse")
	enrollResponse := cer.(*idx.EnrollmentResponse)
	_, continuePolling, err := enrollResponse.OktaVerifyContinuePolling(r.Context())
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	if err != nil {
		log.Fatalf("okta verify confirmation error: %s", err)
	}

	data := struct {
		ContinuePolling bool
		Next            string
	}{continuePolling, "/enrollFactor"}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(resp)
}

func (s *Server) enrollGoogleAuth(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepGoogleAuthenticatorInit) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	enrollResponse, err := enrollResponse.GoogleAuthInit(r.Context())
	if err != nil {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	s.ViewData["QRCode"] = template.URL(enrollResponse.ContextualData().QRcode.Href)
	s.ViewData["SharedSecret"] = template.URL(enrollResponse.ContextualData().SharedSecret)
	s.render("enrollGoogleAuth.gohtml", w, r)
}

func (s *Server) enrollSecurityQuestion(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepSecurityQuestionOptions) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	enrollResponse, questions, err := enrollResponse.SecurityQuestionOptions(r.Context())
	if err != nil {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)
	s.ViewData["Questions"] = questions
	s.render("enrollSecurityQuestion.gohtml", w, r)
}

func (s *Server) handleEnrollSecurityQuestion(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepSecurityQuestionSetup) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}

	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	sq := idx.SecurityQuestion{
		QuestionKey: r.FormValue("question"),
		Question:    r.FormValue("custom_question"),
		Answer:      r.FormValue("answer"),
	}

	enrollResponse, err = enrollResponse.SetupSecurityQuestion(r.Context(), &sq)
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/enrollSecurityQuestion", http.StatusFound)
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

func (s *Server) enrollWebAuthN(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepWebAuthNSetup) {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	enrollResponse, err := enrollResponse.WebAuthNSetup(r.Context())
	if err != nil {
		http.Redirect(w, r, "/enrollFactor", http.StatusFound)
		return
	}
	s.cache.Set("enrollResponse", enrollResponse, time.Minute*5)

	s.ViewData["Challenge"] = enrollResponse.ContextualData().ActivationData.Challenge
	s.ViewData["UserID"] = enrollResponse.ContextualData().ActivationData.User.ID
	s.ViewData["Username"] = enrollResponse.ContextualData().ActivationData.User.Name
	s.ViewData["DisplayName"] = enrollResponse.ContextualData().ActivationData.User.DisplayName
	s.render("enrollWebAuthN.gohtml", w, r)
}

func (s *Server) handleEnrollWebAuthN(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepWebAuthNVerify) {
		http.Redirect(w, r, "/enrollWebAuthN", http.StatusFound)
		return
	}

	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("could not read request body: %v", err)
	}
	defer r.Body.Close()
	var credentials idx.WebAuthNVerifyCredentials
	if err := json.Unmarshal(reqBody, &credentials); err != nil {
		log.Fatalf("could not unmarshal request body: %v", err)
	}

	enrollResponse, err = enrollResponse.WebAuthNVerify(r.Context(), &credentials)
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/enrollWebAuthN", http.StatusFound)
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

func (s *Server) handleEnrollGoogleAuthQRCode(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepGoogleAuthenticatorConfirmation) {
		http.Redirect(w, r, "/enrollGoogleAuth", http.StatusFound)
		return
	}
	s.render("enrollGoogleAuthCode.gohtml", w, r)
}

func (s *Server) handleEnrollGoogleAuthCode(w http.ResponseWriter, r *http.Request) {
	cer, _ := s.cache.Get("enrollResponse")
	if cer == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enrollResponse := cer.(*idx.EnrollmentResponse)
	if !enrollResponse.HasStep(idx.EnrollmentStepGoogleAuthenticatorConfirmation) {
		http.Redirect(w, r, "/enrollGoogleAuth", http.StatusFound)
		return
	}

	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	enrollResponse, err = enrollResponse.GoogleAuthConfirm(r.Context(), r.FormValue("code"))
	if err != nil {
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		s.render("enrollGoogleAuthCode.gohtml", w, r)
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
