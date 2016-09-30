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
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/appengine"
	"golang.org/x/net/context"
)

func init() {
	r := mux.NewRouter()
	r.HandleFunc("/api", apiHandler)
	http.Handle("/", r)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	myToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return myLookupKey(ctx, token.Header["kid"].(string))
	})

	fmt.Printf("%v\n", token.Valid)
	fmt.Printf("%v\n", err)
}

func myLookupKey(ctx context.Context, kid string) (interface{}, error) {
	//fmt.Printf("Kid : %v\n", kid)
	var v map[string]interface{}
	parseJSONFromURL(ctx, "https://accounts.google.com/.well-known/openid-configuration", &v)
	var keys struct{ Keys []gojwk.Key }
	parseJSONFromURL(ctx, v["jwks_uri"].(string), &keys)
	for _, key := range keys.Keys {
		if key.Kid == kid {
			return key.DecodePublicKey()
		}
	}
	return nil, fmt.Errorf("Key not found")
}

func parseJSONFromURL(ctx context.Context, url string, v interface{}) {
	resp, _ := urlfetch.Client(ctx).Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, v)
}
