package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/resource-server/utils"
)

func main() {
	oktaUtils.ParseEnvironment()

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/api/messages", ApiMessagesHandler)

	log.Print("server starting at localhost:8000 ... ")
	err := http.ListenAndServe("localhost:8000", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello!  There's not much to see here :) Please grab one of our front-end samples for use with this sample resource server")
}

func ApiMessagesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, authorization")
	w.Header().Add("Access-Control-Allow-Methods", "GET, POST,OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}

	if !isAuthenticated(r) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - You are not authorized for this request"))
		return
	}

	m1 := Message{1522272240, "I am a robot."}
	m2 := Message{1522268640, "Hello, World!"}
	allMessages := []Message{}
	allMessages = append(allMessages, m1)
	allMessages = append(allMessages, m2)

	mess := Messages{
		allMessages,
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mess)
}

type Message struct {
	Date float64 `json:"date"`
	Text string  `json:"text"`
}

type Messages struct {
	MessageList []Message `json:"messages"`
}

func isAuthenticated(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return false
	}
	tokenParts := strings.Split(authHeader, "Bearer ")
	bearerToken := tokenParts[1]

	tv := map[string]string{}
	tv["aud"] = "api://default"
	tv["cid"] = os.Getenv("SPA_CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	_, err := jv.New().VerifyAccessToken(bearerToken)
	if err != nil {
		return false
	}

	return true
}
