package main

import (
	"context"
	"net/http"
	"time"

	idx "github.com/okta/okta-idx-golang"
)

func NewAccountInitialHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := client.Introspect(context.TODO(), nil)
	if err != nil {
		panic(err)
	}
	memCache.Set(resp.StateHandle, resp, time.Minute*5)
	session, _ := sessionStore.Get(r, "enroll")
	session.Values["initial-enroll-profile-response"] = resp.StateHandle
	session.Save(r, w)
	data := customData{
		IsNewAccount:           true,
		IsInitialAccountCreate: true,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func NewAccountPasscodeHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	session, _ := sessionStore.Get(r, "enroll")
	cr, _ := memCache.Get(session.Values["profile-response"].(string))
	response, err := cr.(*idx.Response).SetPasswordOnEnroll(context.TODO(), password)
	if err != nil {
		panic(err)
	}
	emailResp, err := response.SendEnrollmentEmailVerificationCode(context.TODO())
	if err != nil {
		panic(err)
	}
	delete(session.Values, "profile-response")
	memCache.Set(response.StateHandle, emailResp, time.Minute*5)
	session.Values["email-response"] = response.StateHandle
	session.Save(r, w)
	data := customData{
		IsNewAccount:      true,
		IsWaitingForEmail: true,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func NewAccountEmailHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "enroll")
	er, _ := memCache.Get(session.Values["email-response"].(string))
	code := r.FormValue("code")
	resp, err := er.(*idx.EmailResponse).ConfirmEnrollment(context.TODO(), code)
	if err != nil {
		panic(err)
	}
	delete(session.Values, "email-response")
	memCache.Delete(resp.StateHandle)
	resp, err = resp.Skip(context.TODO())
	if err != nil {
		panic(err)
	}
	exchangeForm := []byte(`{
		"client_secret": "` + client.ClientSecret() + `",
		"code_verifier": "` + string(client.IdxContext().CodeVerifier()[:]) + `"
	}`)
	tokens, err := resp.SuccessResponse.ExchangeCode(context.Background(), exchangeForm)
	if err != nil {
		panic(err)
	}
	session, _ = sessionStore.Get(r, "okta-hosted-login-session-store")
	session.Values["id_token"] = tokens.IDToken
	session.Values["access_token"] = tokens.AccessToken
	session.Save(r, w)
	data := customData{
		IsAuthenticated: true,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func NewAccountIDHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "enroll")
	cr, _ := memCache.Get(session.Values["initial-enroll-profile-response"].(string))
	response, err := cr.(*idx.Response).EnrollProfile(context.TODO(), &idx.UserProfile{
		LastName:  r.FormValue("last_name"),
		FirstName: r.FormValue("first_name"),
		Email:     r.FormValue("email"),
	})
	if err != nil {
		panic(err)
	}
	delete(session.Values, "initial-enroll-profile-response")
	memCache.Set(response.StateHandle, response, time.Minute*5)
	session.Values["profile-response"] = response.StateHandle
	session.Save(r, w)
	data := customData{
		IsNewAccount:  true,
		IsNewPassword: true,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}
