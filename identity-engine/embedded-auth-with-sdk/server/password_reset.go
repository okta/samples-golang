package server

import (
	"context"
	"log"
	"net/http"
	"time"

	idx "github.com/okta/okta-idx-golang"
)

func (s *Server) passwordReset(w http.ResponseWriter, r *http.Request) {
	s.render("resetPassword.gohtml", w, r)
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	// Get session store so we can store our tokens
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("could not get store: %s", err)
	}
	invEmail, ok := s.ViewData["InvalidEmail"]
	var rpr *idx.ResetPasswordResponse
	if !ok || !invEmail.(bool) {
		ir := &idx.IdentifyRequest{
			Identifier: r.FormValue("identifier"),
		}
		var err error
		rpr, err = s.idxClient.InitPasswordReset(context.TODO(), ir)
		if err != nil {
			session.Values["Errors"] = err.Error()
			session.Save(r, w)
			http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
			return
		}
	} else {
		tmp, _ := s.cache.Get("resetPasswordFlow")
		rpr = tmp.(*idx.ResetPasswordResponse)
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
	s.cache.Set("resetPasswordFlow", rpr, time.Minute*5)

	rpr, err = rpr.VerifyEmail(context.TODO())
	if err != nil {
		s.ViewData["InvalidEmail"] = true
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/passwordRecovery", http.StatusFound)
		return
	}
	s.ViewData["InvalidEmail"] = false
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

func (s *Server) passwordResetCode(w http.ResponseWriter, r *http.Request) {
	s.render("resetPasswordCode.gohtml", w, r)
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
