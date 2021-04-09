package main

import (
	"context"
	"net/http"
	"time"

	idx "github.com/okta/okta-idx-golang"
)

func PasswordResetInitialHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := client.Introspect(context.TODO(), nil)
	if err != nil {
		panic(err)
	}
	memCache.Set(resp.StateHandle, resp, time.Minute*5)
	session, _ := sessionStore.Get(r, "password-reset")
	session.Values["initial-password-reset-response"] = resp.StateHandle
	session.Save(r, w)
	data := customData{
		IsResetPassword:        true,
		IsInitialResetPassword: true,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func PasswordResetIDHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	session, _ := sessionStore.Get(r, "password-reset")
	cr, _ := memCache.Get(session.Values["initial-password-reset-response"].(string))
	response, err := cr.(*idx.Response).InitPasswordRecovery(context.TODO(), name)
	if err != nil {
		panic(err)
	}
	emailResp, err := response.SendPasswordResetEmailVerificationCode(context.TODO())
	if err != nil {
		panic(err)
	}
	delete(session.Values, "initial-password-reset-response")
	memCache.Set(response.StateHandle, emailResp, time.Minute*5)
	session.Values["email-response"] = response.StateHandle
	session.Save(r, w)

	data := customData{
		IsResetPassword:   true,
		IsWaitingForEmail: true,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func PasswordResetEmailHandler(w http.ResponseWriter, r *http.Request) {
	data := customData{
		IsResetPassword: true,
		IsNewPassword:   true,
	}
	session, _ := sessionStore.Get(r, "password-reset")
	er, _ := memCache.Get(session.Values["email-response"].(string))
	code := r.FormValue("code")
	resp, err := er.(*idx.EmailResponse).ConfirmReset(context.TODO(), code)
	if err != nil {
		panic(err)
	}
	delete(session.Values, "email-response")
	memCache.Set(resp.StateHandle, resp, time.Minute*5)
	session.Values["password-response"] = resp.StateHandle
	session.Save(r, w)
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func PasswordResetPasscodeHandler(w http.ResponseWriter, r *http.Request) {
	data := customData{
		IsResetPassword: true,
		IsNewPassword:   true,
	}
	session, _ := sessionStore.Get(r, "password-reset")
	er, _ := memCache.Get(session.Values["password-response"].(string))
	password := r.FormValue("password")
	resp, err := er.(*idx.Response).SetPasswordOnReset(context.TODO(), password)
	if err != nil {
		panic(err)
	}
	delete(session.Values, "password-response")
	memCache.Delete(resp.StateHandle)

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
	data.IsAuthenticated = true
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}
