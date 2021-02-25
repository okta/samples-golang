package utils

import (
	"github.com/gorilla/sessions"
	"net/http"
	"os"
)

var sessionStore *sessions.CookieStore

func InitStore() *sessions.CookieStore {
	sessionStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
	sessionStore.Options = &sessions.Options{
		MaxAge:   60 * 15,
		HttpOnly: true,
	}
	return sessionStore
}

func GetSession(w http.ResponseWriter, r *http.Request, sessionStr string) *sessions.Session {
	session, err := sessionStore.Get(r, sessionStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return session
}
