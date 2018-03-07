package main

import (
	"net/http"
	"html/template"
	"os"
	"fmt"
	"encoding/base64"
	"bytes"
)

var tpl *template.Template
var state = "applicationState"

func init() {

	tpl = template.Must(template.ParseGlob("templates/*"))
}

func main() {
	parseEnvironment()

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/authorization-code/callback", CallbackHandler)
	http.ListenAndServe(":8080", nil)
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
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

	// Exchange the code for an access_token
	 exchangeCode(r.URL.Query().Get("code"), r)
	// When access token is returned, verify that it is a valid token

	// Store the token in a cookie
}

func exchangeCode(code string, r *http.Request) string {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(	os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic " + authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-url-encoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}

	fmt.Println(req)

	resp, _ := client.Do(req)

	defer resp.Body.Close()

	return "hi"

}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	type customData struct {
		FirstName string
		IsAuthenticated bool
	}

	data := customData{
		FirstName: getProfileData()["fname"],
		IsAuthenticated: isAuthenticated(),
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", state)
	q.Add("nonce", "nonce")


	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()
	fmt.Println(redirectPath)
	http.Redirect(w, r, redirectPath, http.StatusTemporaryRedirect)
}

func isAuthenticated() bool {
	return false
}

func getProfileData() map[string]string {
	m := make(map[string]string)
	m["fname"] = "BrianRetterer"
	return m
}
