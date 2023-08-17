// +build ignore

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	loggingMiddleware := func(h http.Handler) http.Handler {
		return handlers.LoggingHandler(os.Stdout, h)
	}
	router.Use(loggingMiddleware)

	CSRFMiddleware := csrf.Protect(
		[]byte("place-your-32-byte-long-key-here"),
		csrf.Secure(false),                 // false in development only!
		csrf.RequestHeader("X-CSRF-Token"), // Must be in CORS Allowed and Exposed Headers
	)

	APIRouter := router.PathPrefix("/api").Subrouter()
	APIRouter.Use(CSRFMiddleware)
	APIRouter.HandleFunc("", Get).Methods(http.MethodGet)
	APIRouter.HandleFunc("", Post).Methods(http.MethodPost)

	CORSMiddleware := handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedOriginValidator(
			func(origin string) bool {
				return strings.HasPrefix(origin, "http://localhost")
			},
		),
		handlers.AllowedHeaders([]string{"X-CSRF-Token"}),
		handlers.ExposedHeaders([]string{"X-CSRF-Token"}),
	)

	server := &http.Server{
		Handler:      CORSMiddleware(router),
		Addr:         "localhost:8080",
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	fmt.Println("starting http server on localhost:8080")
	log.Panic(server.ListenAndServe())
}

func Get(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("X-CSRF-Token", csrf.Token(r))
	w.WriteHeader(http.StatusOK)
}

func Post(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
