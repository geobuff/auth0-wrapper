package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

// Response holds the response message.
type Response struct {
	Message string `json:"message"`
}

// Jwks holds a list of json web keys.
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys holds fields related to the JSON Web Key Set for this API.
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// GetJwtMiddleware returns the Auth0 middleware instance we will use to handle authorized endpoints.
func GetJwtMiddleware(audience string, issuer string) *jwtmiddleware.JWTMiddleware {
	return jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(audience, false)
			if !checkAud {
				return token, errors.New("invalid audience")
			}

			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPemCert(token, issuer)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})
}

func getPemCert(token *jwt.Token, issuer string) (string, error) {
	cert := ""
	resp, err := http.Get(fmt.Sprintf("%s.well-known/jwks.json", issuer))

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}
