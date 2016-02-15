package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
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
	fmt.Printf("Kid : %v\n", kid)
	var v map[string]interface{}
	parseJSONFromURL("https://accounts.google.com/.well-known/openid-configuration", &v)
	parseJSONFromURL(v["jwks_uri"].(string), &v)
	for _, keystr := range v["keys"].([]interface{}) {
		if key, ok := keystr.(map[string]interface{}); ok {
			if key["kid"].(string) == kid {
				return createPublicKey(key["n"].(string), key["e"].(string)), nil
			}
		}
	}
	return nil, fmt.Errorf("Key not found")
}

func createPublicKey(nStr, eStr string) *rsa.PublicKey {
	// N part
	nDec, _ := base64.URLEncoding.DecodeString(nStr)
	n := big.NewInt(0)
	n.SetBytes(nDec)

	// E part
	eDec, _ := base64.URLEncoding.DecodeString(eStr)
	var eBytes []byte
	if len(eDec) < 8 {
		eBytes = make([]byte, 8-len(eDec), 8)
		eBytes = append(eBytes, eDec...)
	} else {
		eBytes = eDec
	}
	eReader := bytes.NewReader(eBytes)
	var e uint64
	binary.Read(eReader, binary.BigEndian, &e)

	// Debug ...
	//fmt.Printf("N : %v\n", n)
	//fmt.Printf("E : %v\n", e)

	pk := &rsa.PublicKey{N: n, E: int(e)}

	fmt.Printf("%v", pk)
	return pk
}

func parseJSONFromURL(url string, v interface{}) {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, v)
}
