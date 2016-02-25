package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/mendsley/gojwk"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/api", apiHandler)
	http.Handle("/", r)

	fmt.Println("Application running on port 9999")
	http.ListenAndServe(":9999", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./public/index.html")
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	myToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return myLookupKey(token.Header["kid"].(string))
	})

	fmt.Printf("%v\n", token.Valid)
	fmt.Printf("%v\n", err)
}

func myLookupKey(kid string) (interface{}, error) {
	//fmt.Printf("Kid : %v\n", kid)
	var v map[string]interface{}
	parseJSONFromURL("https://accounts.google.com/.well-known/openid-configuration", &v)
	var keys struct{ Keys []gojwk.Key }
	parseJSONFromURL(v["jwks_uri"].(string), &keys)
	for _, key := range keys.Keys {
		if key.Kid == kid {
			return key.DecodePublicKey()
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
