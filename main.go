package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/api", apiHandler)
	http.Handle("/", r)

	fmt.Println("Application running on port 8080")
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./public/index.html")
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	myToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

	token, _ := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return myLookupKey(token.Header["kid"].(string))
	})

	fmt.Printf("%v", token.Valid)
}

func myLookupKey(kid string) (interface{}, error) {
	var v map[string]interface{}
	parseJSONFromURL("https://accounts.google.com/.well-known/openid-configuration", &v)
	parseJSONFromURL(v["jwks_uri"].(string), &v)
	for _, keystr := range v["keys"].([]interface{}) {
		if key, ok := keystr.(map[string]interface{}); ok {
			if key["kid"].(string) == kid {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("Key not found")
}

func parseJSONFromURL(url string, v interface{}) {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, v)
}
