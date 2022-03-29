package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	loggingMiddleware := func(h http.Handler) http.Handler {
		return handlers.LoggingHandler(os.Stdout, h)
	}
	router.Use(loggingMiddleware)

	wd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}
	// change this directory to point at a different Javascript frontend to serve
	httpStaticAssetsDir := http.Dir(fmt.Sprintf("%s/../frontends/axios/", wd))

	router.PathPrefix("/").Handler(http.FileServer(httpStaticAssetsDir))

	server := &http.Server{
		Handler:      router,
		Addr:         "localhost:8081",
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	fmt.Println("starting http server on localhost:8081")
	log.Panic(server.ListenAndServe())
}
