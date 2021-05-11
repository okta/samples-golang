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
	"path"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/howeyc/fsnotify"
	idx "github.com/okta/okta-idx-golang"
	"github.com/okta/samples-golang/direct-auth/config"
	"github.com/okta/samples-golang/direct-auth/views"
)

type Server struct {
	config    *config.Config
	tpl       *template.Template
	idxClient *idx.Client
	session   *sessions.CookieStore
	view      *views.ViewConfig
	ViewData  ViewData
}

type ViewData map[string]interface{}

var sessionStore = sessions.NewCookieStore([]byte("okta-direct-auth-session-store"))

func NewServer(c *config.Config) *Server {

	idx, err := idx.NewClient()

	if err != nil {
		log.Fatal(err)
	}

	return &Server{
		config:    c,
		idxClient: idx,
		session:   sessionStore,
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

func (s *Server) Run() {
	s.parseTemplates()

	go s.watchForTemplates()

	r := mux.NewRouter()

	// Username/Password Login
	r.HandleFunc("/login/primary", s.loginPrimary).Methods("GET")
	r.HandleFunc("/login/primary", s.handlePrimaryLogin).Methods("POST")

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

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

// BEGIN: Username/Password Login
func (s *Server) loginPrimary(w http.ResponseWriter, r *http.Request) {
	s.render("loginPrimary.gohtml", w, r)
}

func (s *Server) handlePrimaryLogin(w http.ResponseWriter, r *http.Request) {
	lr, err := s.idxClient.InitLogin(context.TODO())
	session, err := sessionStore.Get(r, "direct-auth")
	if err != nil {
		log.Fatalf("Could not initalize login: %s", err.Error())
	}

	ir := &idx.IdentifyRequest{
		Identifier: r.FormValue("identifier"),
		Credentials: idx.Credentials{
			Password: r.FormValue("password"),
		},
	}

	lr, err = lr.Identify(context.TODO(), ir)
	if err != nil {
		fmt.Printf("Identify Request Failure: %s", err.Error())
		session.Values["Errors"] = err.Error()
		session.Save(r, w)
		http.Redirect(w, r, "/login/primary", http.StatusFound)
		return
	}

	fmt.Printf("%+v\n", lr.Token() != nil)

	if lr.Token() != nil {

		if err != nil {
			log.Fatalf("could not get store: %s", err)
		}
		session.Values["access_token"] = lr.Token().AccessToken
		session.Values["id_token"] = lr.Token().IDToken
		err = session.Save(r, w)
		if err != nil {
			log.Fatalf("could not save access token: %s", err)
		}
	}

	fmt.Printf("%+v\n", lr.Token())

	http.Redirect(w, r, "/", http.StatusFound)

}

// END: Username/Password Login

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
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

	fmt.Printf("%s\n", session.Values["access_token"])

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}
