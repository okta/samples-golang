package main

import (
	"net/http"
	oktaUtils "github.com/okta/samples-golang/resource-server/utils"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"fmt"
	"strings"
	"os"
)

func main() {
	oktaUtils.ParseEnvironment()

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/api/messages", ApiMessagesHandler)

	http.ListenAndServe(":8080", nil)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello!  There's not much to see here :) Please grab one of our front-end samples for use with this sample resource server")
}

func ApiMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - You are not authorized for this request"))
		return
	}

	messages := []byte(`"messages": [{"date": 1522272240, "text": "I am a robot."},{"date": 1522268640, 
"text": "Hello, World!"}]`)


	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(messages)

}

func isAuthenticated(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}
	tokenParts := strings.Split(authHeader, "Bearer")
	bearerToken := tokenParts[1]

	tv := map[string]string{}
	tv["aud"] = "api://default"
	jv := verifier.JwtVerifier{
		Issuer: os.Getenv("ISSUER"),
		ClientId: os.Getenv("CLIENT_ID"),
		ClaimsToValidate: tv,
	}

	_, err := jv.New().Verify(bearerToken)

	if err != nil {
		return false
	}

	return true
}
